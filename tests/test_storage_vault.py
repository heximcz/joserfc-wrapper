import builtins
import subprocess
import sys
import uuid
from typing import Any
from unittest.mock import patch

import pytest
from hvac.exceptions import InvalidPath, InvalidRequest

from joserfc_wrapper import AbstractKeyStorage, KeysSaveError, StorageVault
from joserfc_wrapper.token_header import jti_digest

KID1, KID2, KID3 = (uuid.uuid4().hex for _ in range(3))

KEYS = {
    "keys": {"private": {}, "public": {}, "secret": {}},
    "created": 1,
}
CAS_ERROR = InvalidRequest(
    "check-and-set parameter did not match the current version"
)


@pytest.fixture
def client():
    """Mocked hvac client"""
    with patch("hvac.Client") as client:
        yield client.return_value


def v2_secret(data: dict, version: int) -> dict:
    return {"data": {"data": data, "metadata": {"version": version}}}


def test_is_key_storage(client):
    assert isinstance(StorageVault("url", "token", "mount"), AbstractKeyStorage)


def test_kv_v1_is_removed(client):
    """KV v1 was removed in 1.0.0"""
    options: dict[str, Any] = {"kv_version": 1}
    with pytest.raises(TypeError):
        StorageVault("url", "token", "mount", **options)


class TestKvV2:
    @pytest.fixture
    def kv(self, client):
        return client.secrets.kv.v2

    @pytest.fixture
    def vault(self, client) -> StorageVault:
        return StorageVault("url", "token", "mount")

    def test_save_keys(self, vault, kv):
        vault.save_keys(KID1, KEYS)

        paths = [
            c.kwargs["path"] for c in kv.create_or_update_secret.call_args_list
        ]
        assert paths == [KID1, "last-key-id"]

    def test_load_keys(self, vault, kv):
        kv.read_secret_version.side_effect = [
            v2_secret({"kid": KID1}, 3),
            v2_secret(KEYS, 1),
        ]

        assert vault.load_keys() == (KID1, {"data": KEYS})

    def test_update_metadata_gives_up(self, vault, kv):
        kv.read_secret_version.return_value = v2_secret(dict(KEYS), 1)
        kv.create_or_update_secret.side_effect = CAS_ERROR

        with pytest.raises(KeysSaveError):
            vault.update_metadata(KID1, {"revoked": 1})

    def test_other_errors_are_raised(self, vault, kv):
        kv.read_secret_version.return_value = v2_secret(dict(KEYS), 1)
        kv.create_or_update_secret.side_effect = InvalidRequest("other")

        with pytest.raises(InvalidRequest, match="other"):
            vault.update_metadata(KID1, {"revoked": 1})

    def test_replace_last_keys(self, vault, kv):
        kv.read_secret_version.return_value = v2_secret({"kid": KID1}, 4)

        assert vault.replace_last_keys(KID1, KID2, KEYS) == KID2
        keys_call, last_call = kv.create_or_update_secret.call_args_list
        assert keys_call.kwargs["path"] == KID2
        assert last_call.kwargs == {
            "mount_point": "mount",
            "path": "last-key-id",
            "secret": {"kid": KID2},
            "cas": 4,
        }

    def test_replace_last_keys_already_rotated(self, vault, kv):
        kv.read_secret_version.return_value = v2_secret({"kid": KID3}, 5)

        assert vault.replace_last_keys(KID1, KID2, KEYS) == KID3
        kv.create_or_update_secret.assert_not_called()

    def test_replace_last_keys_conflict_removes_keys(self, vault, kv):
        kv.read_secret_version.side_effect = [
            v2_secret({"kid": KID1}, 4),
            v2_secret({"kid": KID3}, 5),
        ]
        kv.create_or_update_secret.side_effect = [None, CAS_ERROR]

        assert vault.replace_last_keys(KID1, KID2, KEYS) == KID3
        kv.delete_metadata_and_all_versions.assert_called_once_with(
            path=KID2, mount_point="mount"
        )


@pytest.mark.filterwarnings("ignore:KV v1:DeprecationWarning")
class TestLifecycle:
    @pytest.fixture
    def kv(self, client):
        return client.secrets.kv.v2

    @pytest.fixture
    def vault(self, client) -> StorageVault:
        return StorageVault("url", "token", "mount")

    def test_list_kids(self, vault, kv):
        kids = sorted(uuid.uuid4().hex for _ in range(2))
        kv.list_secrets.return_value = {
            "data": {"keys": [kids[1], "last-key-id", kids[0]]}
        }

        assert vault.list_kids() == kids

    def test_delete_keys(self, vault, kv):
        kid = uuid.uuid4().hex
        vault.delete_keys(kid)

        kv.delete_metadata_and_all_versions.assert_called_once_with(
            path=kid, mount_point="mount"
        )

    def test_delete_invalid_kid(self, vault, kv):
        with pytest.raises(ValueError):
            vault.delete_keys("last-key-id")
        kv.delete_metadata_and_all_versions.assert_not_called()

    def test_update_metadata(self, vault, kv):
        kv.read_secret_version.return_value = v2_secret(dict(KEYS), 3)

        vault.update_metadata(KID1, {"retired": 5})

        kv.create_or_update_secret.assert_called_once_with(
            mount_point="mount",
            path=KID1,
            secret={**KEYS, "retired": 5},
            cas=3,
        )

    def test_update_metadata_retries_on_conflict(self, vault, kv):
        kv.read_secret_version.side_effect = [
            v2_secret(dict(KEYS), 3),
            v2_secret({**KEYS, "counter": 1}, 4),
        ]
        kv.create_or_update_secret.side_effect = [CAS_ERROR, None]

        vault.update_metadata(KID1, {"revoked": 7})

        last = kv.create_or_update_secret.call_args.kwargs
        assert last["cas"] == 4
        assert last["secret"] == {**KEYS, "counter": 1, "revoked": 7}

    def test_revoke_jti(self, vault, kv):
        vault.revoke_jti("jti1", 100)

        call = kv.create_or_update_secret.call_args.kwargs
        assert call["path"] == f"revoked/{jti_digest('jti1')}"
        assert call["secret"] == {"exp": 100}

    def test_is_jti_revoked(self, vault, kv):
        kv.read_secret_version.side_effect = [
            v2_secret({"exp": 100}, 1),
            InvalidPath(),
        ]

        assert vault.is_jti_revoked("jti1")
        assert not vault.is_jti_revoked("jti2")
        path = kv.read_secret_version.call_args.kwargs["path"]
        assert path == f"revoked/{jti_digest('jti2')}"

    def test_prune_revoked(self, vault, kv):
        kv.list_secrets.return_value = {"data": {"keys": ["a", "b", "c"]}}
        kv.read_secret_version.side_effect = [
            v2_secret({"exp": 50}, 1),
            v2_secret({"exp": 150}, 1),
            InvalidPath(),  # deleted by another process
        ]

        assert vault.prune_revoked(100) == 1
        kv.delete_metadata_and_all_versions.assert_called_once_with(
            path="revoked/a", mount_point="mount"
        )

    def test_prune_revoked_nothing_revoked(self, vault, kv):
        kv.list_secrets.side_effect = InvalidPath()

        assert vault.prune_revoked(100) == 0


def test_hvac_not_installed():
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "hvac":
            raise ImportError("No module named 'hvac'")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=fake_import):
        with pytest.raises(ImportError, match=r"joserfc-wrapper\[vault\]"):
            StorageVault("url", "token", "mount")
