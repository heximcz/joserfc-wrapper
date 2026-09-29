"""WrapJWK without state (1.0.0)"""

import copy
import json
import threading
import time
from unittest.mock import patch

import pytest

from joserfc_wrapper import (
    AbstractKeyStorage,
    ConfigurationError,
    KeysLoadError,
    KeysNotFoundError,
    KeysSaveError,
    ObjectTypeError,
    WrapJWK,
    WrapJWT,
)
from joserfc_wrapper.testing import check_storage
from joserfc_wrapper.wrap_jwk import generate_keys

from .conftest import key_part, key_record, last_kid

DAY = 86400


class MinimalStorage(AbstractKeyStorage):
    """
    The smallest custom storage: only the required methods (in memory),
    without listing keys and without token revocation
    """

    not_found_errors = (KeyError,)

    def __init__(self) -> None:
        self.data: dict = {}
        self.lock = threading.Lock()

    def get_last_kid(self) -> str:
        return self.data["last-key-id"]["kid"]

    def load_keys(self, kid: str = "") -> tuple[str, dict]:
        kid = kid or self.get_last_kid()
        return kid, {"data": copy.deepcopy(self.data[kid])}

    def save_keys(self, kid: str, keys: dict) -> None:
        with self.lock:
            self.data[kid] = copy.deepcopy(keys)
            self.data["last-key-id"] = {"kid": kid}

    def save_last_kid(self, kid: str) -> None:
        with self.lock:
            self.data["last-key-id"] = {"kid": kid}

    def replace_last_keys(self, last_kid: str, kid: str, keys: dict) -> str:
        with self.lock:
            current = self.data.get("last-key-id", {}).get("kid")
            if current != last_kid:
                return current
            self.data[kid] = copy.deepcopy(keys)
            self.data["last-key-id"] = {"kid": kid}
            return kid

    def update_metadata(self, kid: str, metadata: dict) -> None:
        with self.lock:
            self.data[kid].update(metadata)


def later(seconds: int):
    """Patch the current time"""
    return patch("time.time", return_value=time.time() + seconds)


def test_requires_key_storage():
    with pytest.raises(ObjectTypeError):
        WrapJWK(object())  # type: ignore[arg-type]


def test_storage_property(storage):
    assert WrapJWK(storage).storage is storage


def test_minimal_storage():
    check_storage(MinimalStorage())


def test_storage_without_required_methods():
    class Incomplete(AbstractKeyStorage):
        def get_last_kid(self) -> str:
            return ""

        def load_keys(self, kid: str = "") -> tuple[str, dict]:
            return kid, {}

        def save_keys(self, kid: str, keys: dict) -> None:
            pass

        def save_last_kid(self, kid: str) -> None:
            pass

    # replace_last_keys and update_metadata are required since 1.0.0
    with pytest.raises(TypeError, match="replace_last_keys"):
        Incomplete()  # type: ignore[abstract]


# generate_keys and rotate


@pytest.mark.parametrize(
    "algorithm, kty, crv",
    [("ES256", "EC", "P-256"), ("Ed25519", "OKP", "Ed25519")],
)
def test_generate_keys(algorithm, kty, crv):
    kid, record = generate_keys(algorithm)

    assert set(record) == {"keys", "created"}, "no counter since 1.0.0"
    assert set(record["keys"]) == {"private", "public", "secret"}
    public = record["keys"]["public"]
    assert (public["kty"], public["crv"]) == (kty, crv)
    assert "d" in record["keys"]["private"] and "d" not in public
    assert record["keys"]["secret"]["kty"] == "oct"
    assert abs(record["created"] - time.time()) <= 2
    assert len(kid) == 43


def test_generate_new_kid():
    assert generate_keys()[0] != generate_keys()[0]


def test_rotate_creates_first_keys(storage):
    kid = WrapJWK(storage).rotate()

    assert storage.get_last_kid() == kid


def test_rotate_retires_previous_keys(jwk, storage):
    first = last_kid(jwk)

    second = jwk.rotate()

    assert storage.get_last_kid() == second != first
    assert key_record(jwk, first)["retired"] == key_record(jwk)["created"]


def test_rotate_ed25519(jwk):
    kid = jwk.rotate("Ed25519")

    assert key_part(jwk, "public", kid)["kty"] == "OKP"


@pytest.mark.parametrize("algorithm", ["RS256", "EdDSA", "HS256", ""])
def test_unsupported_algorithm(jwk, algorithm):
    with pytest.raises(ConfigurationError, match="Unsupported algorithm"):
        jwk.rotate(algorithm)
    with pytest.raises(ConfigurationError):
        WrapJWT(jwk, key_algorithm=algorithm)


def test_rotate_keeps_keys_of_concurrent_rotation(jwk, storage):
    """Another process rotated the keys in the meantime"""
    other = generate_keys()
    original = storage.replace_last_keys

    def concurrent(last_kid: str, kid: str, keys: dict) -> str:
        storage.save_keys(*other)
        return original(last_kid, kid, keys)

    with patch.object(storage, "replace_last_keys", side_effect=concurrent):
        assert jwk.rotate() == other[0]
    assert storage.get_last_kid() == other[0]


def test_rotate_save_error(jwk, storage):
    with patch.object(storage, "replace_last_keys", side_effect=OSError("x")):
        with pytest.raises(KeysSaveError, match="OSError"):
            jwk.rotate()


# reserve_signing_key


def test_reserve_signing_key(jwk):
    kid, private = jwk.reserve_signing_key()

    assert kid == last_kid(jwk)
    assert private == key_part(jwk, "private")


def test_reserve_signing_key_without_keys(storage):
    with pytest.raises(KeysNotFoundError):
        WrapJWK(storage).reserve_signing_key()


def test_reserve_signing_key_rotates_old_keys(jwk):
    first = last_kid(jwk)

    assert jwk.reserve_signing_key(max_key_age=DAY)[0] == first
    with later(DAY + 1):
        kid, _ = jwk.reserve_signing_key(max_key_age=DAY, algorithm="Ed25519")
    assert kid != first and kid == last_kid(jwk)
    assert key_part(jwk, "public", kid)["kty"] == "OKP"


def test_reserve_signing_key_rotates_revoked_keys(jwk, storage):
    first = last_kid(jwk)
    storage.update_metadata(first, {"revoked": int(time.time())})

    assert jwk.reserve_signing_key()[0] != first


def test_keys_without_created_rotate_once(jwk, storage, tmp_path):
    """Keys of versions older than 0.5.0 have no creation time"""
    first = last_kid(jwk)
    path = tmp_path / f"{first}.json"
    record = json.loads(path.read_text())
    del record["data"]["created"]
    path.write_text(json.dumps(record))

    second = jwk.reserve_signing_key(max_key_age=DAY)[0]

    assert second != first
    assert jwk.reserve_signing_key(max_key_age=DAY)[0] == second


def test_reserve_signing_key_gives_up(jwk, storage):
    """Other processes revoke every new key"""
    original = storage.load_keys

    def always_revoked(kid: str = "") -> tuple[str, dict]:
        loaded_kid, result = original(kid)
        result["data"]["revoked"] = 1
        return loaded_kid, result

    with patch.object(storage, "load_keys", side_effect=always_revoked):
        with pytest.raises(KeysSaveError, match="too many rotations"):
            jwk.reserve_signing_key()


def test_reserve_signing_key_storage_error(jwk, storage):
    with patch.object(storage, "load_keys", side_effect=OSError("down")):
        with pytest.raises(KeysLoadError, match="OSError"):
            jwk.reserve_signing_key()


def test_incomplete_keys_in_storage(jwk, tmp_path):
    path = tmp_path / f"{last_kid(jwk)}.json"
    path.write_text(json.dumps({"data": {"created": 1}}))

    with pytest.raises(KeysLoadError):
        jwk.reserve_signing_key()
    with pytest.raises(KeysLoadError):
        jwk.load_secret_key()


# revoke


def test_revoke_keeps_algorithm_of_revoked_keys(jwk):
    kid = jwk.rotate("Ed25519")

    jwk.revoke(kid)

    assert key_part(jwk, "public")["kty"] == "OKP"
    assert key_record(jwk, kid)["revoked"] is not None


def test_revoke_with_other_algorithm(jwk):
    kid = last_kid(jwk)

    jwk.revoke(kid, algorithm="Ed25519")

    assert key_part(jwk, "public")["kty"] == "OKP"


def test_revoke_unknown_keys(jwk):
    with pytest.raises(KeysNotFoundError):
        jwk.revoke(generate_keys()[0])


# loading keys


def test_load_verification_key(jwk):
    public, revoked = jwk.load_verification_key(last_kid(jwk))

    assert public == key_part(jwk, "public") and revoked is None


def test_load_unknown_keys(jwk):
    with pytest.raises(KeysNotFoundError):
        jwk.load_verification_key(generate_keys()[0])
    with pytest.raises(KeysNotFoundError):
        jwk.load_secret_key(generate_keys()[0])


def test_load_secret_key(jwk):
    kid, secret = jwk.load_secret_key()

    assert kid == last_kid(jwk)
    assert secret == key_part(jwk, "secret")


def test_list_keys_without_listing():
    jwk = WrapJWK(MinimalStorage())
    jwk.rotate()

    with pytest.raises(KeysLoadError, match="does not support listing"):
        jwk.list_keys()


def test_list_keys(jwk):
    first = last_kid(jwk)
    second = jwk.rotate("Ed25519")

    keys = jwk.list_keys()

    assert [k["kid"] for k in keys] == [first, second]
    assert [k["algorithm"] for k in keys] == ["ES256", "Ed25519"]
    assert keys[1]["last"] and not keys[0]["last"]
    assert all("private" not in k and "counter" not in k for k in keys)
