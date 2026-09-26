from unittest.mock import patch

import pytest
from hvac.exceptions import InvalidRequest

from joserfc_wrapper import AbstractKeyStorage, KeysSaveError, StorageVault

KEYS = {
    "keys": {"private": {}, "public": {}, "secret": {}},
    "counter": 0,
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


def test_unsupported_kv_version(client):
    with pytest.raises(ValueError):
        StorageVault("url", "token", "mount", kv_version=3)


class TestKvV1:
    @pytest.fixture
    def kv(self, client):
        return client.secrets.kv.v1

    @pytest.fixture
    def vault(self, client) -> StorageVault:
        return StorageVault("url", "token", "mount", kv_version=1)

    def test_save_keys(self, vault, kv):
        vault.save_keys("kid1", KEYS)

        keys_call, last_call = kv.create_or_update_secret.call_args_list
        assert keys_call.kwargs == {
            "mount_point": "mount",
            "path": "kid1",
            "secret": KEYS,
        }
        assert last_call.kwargs == {
            "mount_point": "mount",
            "path": "last-key-id",
            "secret": {"kid": "kid1"},
        }

    def test_load_last_keys(self, vault, kv):
        kv.read_secret.side_effect = [
            {"data": {"kid": "kid1"}},
            {"data": KEYS},
        ]

        assert vault.load_keys() == ("kid1", {"data": KEYS})
        paths = [c.kwargs["path"] for c in kv.read_secret.call_args_list]
        assert paths == ["last-key-id", "kid1"]

    def test_increase_counter_keeps_last_kid(self, vault, kv):
        kv.read_secret.side_effect = [
            {"data": {"kid": "kid2"}},
            {"data": KEYS},
        ]

        assert vault.increase_counter("kid1") == 1
        writes = [c.kwargs for c in kv.create_or_update_secret.call_args_list]
        assert writes[0]["secret"]["counter"] == 1
        # the last Key ID is restored after 'save_keys'
        assert writes[-1] == {
            "mount_point": "mount",
            "path": "last-key-id",
            "secret": {"kid": "kid2"},
        }


class TestKvV2:
    @pytest.fixture
    def kv(self, client):
        return client.secrets.kv.v2

    @pytest.fixture
    def vault(self, client) -> StorageVault:
        return StorageVault("url", "token", "mount")

    def test_save_keys(self, vault, kv):
        vault.save_keys("kid1", KEYS)

        paths = [
            c.kwargs["path"] for c in kv.create_or_update_secret.call_args_list
        ]
        assert paths == ["kid1", "last-key-id"]

    def test_load_keys(self, vault, kv):
        kv.read_secret_version.side_effect = [
            v2_secret({"kid": "kid1"}, 3),
            v2_secret(KEYS, 1),
        ]

        assert vault.load_keys() == ("kid1", {"data": KEYS})

    def test_increase_counter(self, vault, kv):
        kv.read_secret_version.return_value = v2_secret(
            {**KEYS, "counter": 4}, 7
        )

        assert vault.increase_counter("kid1") == 5
        kv.create_or_update_secret.assert_called_once_with(
            mount_point="mount",
            path="kid1",
            secret={**KEYS, "counter": 5},
            cas=7,
        )

    def test_increase_counter_limit(self, vault, kv):
        kv.read_secret_version.return_value = v2_secret(
            {**KEYS, "counter": 5}, 7
        )

        assert vault.increase_counter("kid1", limit=5) is None
        kv.create_or_update_secret.assert_not_called()

    def test_increase_counter_retries_on_conflict(self, vault, kv):
        kv.read_secret_version.side_effect = [
            v2_secret({**KEYS, "counter": 1}, 1),
            v2_secret({**KEYS, "counter": 2}, 2),
        ]
        kv.create_or_update_secret.side_effect = [CAS_ERROR, None]

        assert vault.increase_counter("kid1") == 3
        assert kv.create_or_update_secret.call_args.kwargs["cas"] == 2

    def test_increase_counter_gives_up(self, vault, kv):
        kv.read_secret_version.return_value = v2_secret(KEYS, 1)
        kv.create_or_update_secret.side_effect = CAS_ERROR

        with pytest.raises(KeysSaveError):
            vault.increase_counter("kid1")

    def test_other_errors_are_raised(self, vault, kv):
        kv.read_secret_version.return_value = v2_secret(KEYS, 1)
        kv.create_or_update_secret.side_effect = InvalidRequest("other")

        with pytest.raises(InvalidRequest):
            vault.increase_counter("kid1")

    def test_replace_last_keys(self, vault, kv):
        kv.read_secret_version.return_value = v2_secret({"kid": "kid1"}, 4)

        assert vault.replace_last_keys("kid1", "kid2", KEYS) == "kid2"
        keys_call, last_call = kv.create_or_update_secret.call_args_list
        assert keys_call.kwargs["path"] == "kid2"
        assert last_call.kwargs == {
            "mount_point": "mount",
            "path": "last-key-id",
            "secret": {"kid": "kid2"},
            "cas": 4,
        }

    def test_replace_last_keys_already_rotated(self, vault, kv):
        kv.read_secret_version.return_value = v2_secret({"kid": "kid3"}, 5)

        assert vault.replace_last_keys("kid1", "kid2", KEYS) == "kid3"
        kv.create_or_update_secret.assert_not_called()

    def test_replace_last_keys_conflict_removes_keys(self, vault, kv):
        kv.read_secret_version.side_effect = [
            v2_secret({"kid": "kid1"}, 4),
            v2_secret({"kid": "kid3"}, 5),
        ]
        kv.create_or_update_secret.side_effect = [None, CAS_ERROR]

        assert vault.replace_last_keys("kid1", "kid2", KEYS) == "kid3"
        kv.delete_metadata_and_all_versions.assert_called_once_with(
            path="kid2", mount_point="mount"
        )
