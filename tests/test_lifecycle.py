"""Key lifecycle: rotation by age, revoke, prune, max_token_lifetime"""

import json
import time
from unittest.mock import patch

import pytest

from joserfc_wrapper import (
    ConfigurationError,
    CreateTokenError,
    KeysLoadError,
    TokenKeyRevokedError,
    WrapJWK,
    WrapJWT,
)

from .conftest import key_record, last_kid
from .test_jwk import MinimalStorage

ISS, AUD = "https://example.com", "api"
DAY = 86400


def now() -> int:
    return int(time.time())


def jwt_for(jwk: WrapJWK, **config) -> WrapJWT:
    return WrapJWT(jwk, issuer=ISS, audience=AUD, **config)


def later(seconds: int):
    """Patch the current time"""
    return patch("time.time", return_value=time.time() + seconds)


# metadata


def test_new_keys_have_created(jwk):
    record = key_record(jwk)

    assert abs(record["created"] - now()) <= 2
    assert "retired" not in record and "revoked" not in record


def test_create_does_not_write_to_the_storage(jwk, storage, tmp_path):
    """No counter since 1.0.0"""
    path = tmp_path / f"{last_kid(jwk)}.json"
    before = path.read_text()

    with patch.object(storage, "update_metadata") as update:
        jwt_for(jwk).create({"sub": "1"}, exp=60)

    assert path.read_text() == before
    update.assert_not_called()


def test_file_update_metadata(jwk, storage):
    storage.update_metadata(last_kid(jwk), {"revoked": 123})

    record = key_record(jwk)
    assert record["revoked"] == 123 and "created" in record


def test_file_list_and_delete(jwk, storage, tmp_path):
    first = last_kid(jwk)
    second = jwk.rotate()
    (tmp_path / "notes.json").write_text("{}")

    assert storage.list_kids() == sorted([first, second])

    storage.delete_keys(first)
    assert storage.list_kids() == [second]
    with pytest.raises(ValueError):
        storage.delete_keys("../last-key-id")


# rotation by age


def test_rotation_by_max_key_age(jwk):
    first = last_kid(jwk)
    jwt = jwt_for(jwk, max_key_age=DAY)

    jwt.create({"sub": "1"}, exp=60)
    assert last_kid(jwk) == first

    with later(DAY + 1):
        token = jwt.create({"sub": "1"}, exp=60)
    second = last_kid(jwk)
    assert second != first
    assert jwt.decode(token).header["kid"] == second
    assert key_record(jwk, first)["retired"] == key_record(jwk)["created"]


def test_rotation_to_ed25519(jwk):
    jwt = jwt_for(jwk, max_key_age=DAY, key_algorithm="Ed25519")
    old = jwt.create({"sub": "1"}, exp=60)

    with later(DAY + 1):
        new = jwt.create({"sub": "1"}, exp=60)
        assert jwt.verify(new)

    # the algorithm of the key signs, the old token stays valid
    assert jwt.decode(old).header["alg"] == "ES256"
    assert jwt.decode(new).header["alg"] == "Ed25519"
    assert jwt.verify(old)


def test_revoked_last_keys_are_not_used(jwk, storage):
    """A revoked last key (e.g. revoked by another tool) is rotated"""
    first = last_kid(jwk)
    storage.update_metadata(first, {"revoked": now()})

    token = jwt_for(jwk).create({"sub": "1"}, exp=60)

    assert jwt_for(jwk).verify(token).header["kid"] != first


# revoke


def test_revoke_keys(jwk, storage):
    first = last_kid(jwk)
    token = jwt_for(jwk).create({"sub": "1"}, exp=60)
    second = jwk.rotate()

    jwk.revoke(first)

    with pytest.raises(TokenKeyRevokedError):
        jwt_for(jwk).verify(token)
    assert storage.get_last_kid() == second


def test_revoke_last_keys_generates_new_keys(jwk, storage):
    first = last_kid(jwk)
    token = jwt_for(jwk).create({"sub": "1"}, exp=60)

    jwk.revoke(first)

    assert storage.get_last_kid() != first
    with pytest.raises(TokenKeyRevokedError):
        jwt_for(jwk).verify(token)
    # creating tokens continues with the new keys
    new = jwt_for(jwk).create({"sub": "1"}, exp=60)
    assert jwt_for(jwk).verify(new).header["kid"] == storage.get_last_kid()


# prune


def test_prune(jwk, storage):
    first = last_kid(jwk)
    second = jwk.rotate()
    last = jwk.rotate()

    # retired keys are kept until their tokens expire
    assert not jwk.prune(max_token_lifetime=3600)

    with later(3600 + 2):
        deleted = jwk.prune(max_token_lifetime=3600)

    assert sorted(deleted) == sorted([first, second])
    assert storage.list_kids() == [last]


def test_prune_leeway(jwk):
    jwk.rotate()

    with later(3600 + 2):
        assert not jwk.prune(max_token_lifetime=3600, leeway=60)


def test_prune_keeps_keys_of_0_4(jwk, storage, tmp_path):
    """Keys of versions older than 0.5.0 have no times, never deleted"""
    first = last_kid(jwk)
    jwk.rotate()
    path = tmp_path / f"{first}.json"
    record = json.loads(path.read_text())
    del record["data"]["retired"], record["data"]["created"]
    path.write_text(json.dumps(record))

    with later(10 * DAY):
        assert not jwk.prune(max_token_lifetime=3600)
        assert not jwk.prune(max_token_lifetime=3600)
    assert first in storage.list_kids()


def test_prune_retires_keys_never_retired(jwk, storage, tmp_path):
    """Not the last keys, with created, without retired: retired, later deleted"""
    first = last_kid(jwk)
    jwk.rotate()
    path = tmp_path / f"{first}.json"
    record = json.loads(path.read_text())
    del record["data"]["retired"]
    path.write_text(json.dumps(record))

    with later(10 * DAY):
        assert not jwk.prune(max_token_lifetime=3600)
    assert key_record(jwk, first)["retired"] is not None
    with later(10 * DAY + 3602):
        assert jwk.prune(max_token_lifetime=3600) == [first]


def test_prune_revoked_keys(jwk):
    first = last_kid(jwk)
    jwk.revoke(first)

    with later(3600 + 2):
        assert jwk.prune(max_token_lifetime=3600) == [first]


@pytest.mark.parametrize(
    "lifetime, leeway", [(0, 0), (-1, 0), (60, -1), (True, 0)]
)
def test_prune_invalid_parameters(jwk, lifetime, leeway):
    with pytest.raises(ConfigurationError):
        jwk.prune(max_token_lifetime=lifetime, leeway=leeway)


def test_prune_storage_without_listing():
    jwk = WrapJWK(MinimalStorage())
    jwk.rotate()

    with pytest.raises(KeysLoadError, match="does not support listing"):
        jwk.prune(max_token_lifetime=60)


def test_wrapjwt_prune(jwk):
    jwk.rotate()

    with pytest.raises(ConfigurationError):
        jwt_for(jwk).prune()
    with later(3600 + 2):
        assert len(jwt_for(jwk, max_token_lifetime=3600).prune()) == 1


# max_token_lifetime


def test_max_token_lifetime(jwk):
    jwt = jwt_for(jwk, max_token_lifetime=3600)

    assert jwt.verify(jwt.create({"sub": "1"}, exp=3600))
    with pytest.raises(CreateTokenError, match="max_token_lifetime"):
        jwt.create({"sub": "1"}, exp=3601)
    with pytest.raises(CreateTokenError, match="max_token_lifetime"):
        jwt.create({"sub": "1", "exp": now() + 7200})
    with pytest.raises(CreateTokenError, match="required"):
        jwt.create({"sub": "1"})


def test_max_token_lifetime_with_default_exp(jwk):
    jwt = jwt_for(jwk, max_token_lifetime=3600, default_exp=600)

    assert jwt.verify(jwt.create({"sub": "1"}))
    with pytest.raises(ConfigurationError):
        jwt_for(jwk, max_token_lifetime=600, default_exp=3600)
