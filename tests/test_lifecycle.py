"""Key lifecycle: metadata, rotation by age, rotate, revoke, prune (0.5.0)"""

import json
import time
import uuid
from unittest.mock import patch

import pytest

from joserfc_wrapper import (
    ConfigurationError,
    CreateTokenException,
    KeysLoadError,
    KeysNotFoundError,
    StorageFile,
    TokenKeyRevokedError,
    WrapJWK,
    WrapJWT,
)

from .test_jwk import LegacyStorage

CLAIMS = {"iss": "https://example.com", "aud": "api", "uid": 1}
DAY = 86400


def now() -> int:
    return int(time.time())


def jwt_for(jwk: WrapJWK, **config) -> WrapJWT:
    return WrapJWT(jwk, issuer=CLAIMS["iss"], audience=CLAIMS["aud"], **config)


def record(tmp_path, kid: str) -> dict:
    return json.loads((tmp_path / f"{kid}.json").read_text())["data"]


def later(seconds: int):
    """Patch the current time"""
    return patch("time.time", return_value=time.time() + seconds)


# metadata


def test_generate_keys_sets_created(jwk):
    assert abs(jwk.get_created() - now()) <= 2
    assert jwk.get_retired() is None
    assert jwk.get_revoked() is None
    assert not jwk.is_revoked()


def test_metadata_saved_and_kept_by_counter(jwk, tmp_path):
    """increase_counter must not drop metadata of the record"""
    created = jwk.get_created()
    WrapJWT(jwk).create(dict(CLAIMS), exp=60)

    data = record(tmp_path, jwk.get_kid())
    assert data["counter"] == 1
    assert data["created"] == created


def test_legacy_default_counter_keeps_metadata():
    storage = LegacyStorage()
    jwk = WrapJWK(storage)
    jwk.generate_keys()
    jwk.save_keys()

    WrapJWT(jwk).create(dict(CLAIMS), exp=60)

    assert storage.data[jwk.get_kid()]["created"] == jwk.get_created()


def test_keys_without_metadata_load(storage, tmp_path):
    """Keys saved by versions older than 0.5.0 have no metadata"""
    kid = uuid.uuid4().hex
    old = WrapJWK(storage)
    old.generate_keys()
    data = {
        "keys": {
            "private": old.get_private_key(),
            "public": old.get_public_key(),
            "secret": old.get_secret_key(),
        },
        "counter": 3,
    }
    (tmp_path / f"{kid}.json").write_text(json.dumps({"data": data}))
    (tmp_path / "last-key-id.json").write_text(json.dumps({"kid": kid}))

    jwk = WrapJWK(storage)
    jwk.load_keys()

    assert jwk.get_kid() == kid
    assert jwk.get_created() is None
    assert not jwk.is_revoked()


def test_file_update_metadata(jwk, storage, tmp_path):
    storage.update_metadata(jwk.get_kid(), {"revoked": 123})

    data = record(tmp_path, jwk.get_kid())
    assert data["revoked"] == 123
    assert data["created"] == jwk.get_created()


def test_legacy_update_metadata_keeps_last_kid():
    storage = LegacyStorage()
    jwk = WrapJWK(storage)
    jwk.generate_keys()
    jwk.save_keys()
    first = jwk.get_kid()
    jwk.generate_keys()
    jwk.save_keys()

    storage.update_metadata(first, {"revoked": 1})

    assert storage.data[first]["revoked"] == 1
    assert storage.get_last_kid() == jwk.get_kid()


def test_file_list_and_delete(jwk, storage, tmp_path):
    first = jwk.get_kid()
    jwk.rotate()
    (tmp_path / "notes.json").write_text("{}")

    assert storage.list_kids() == sorted([first, jwk.get_kid()])

    storage.delete_keys(first)
    assert storage.list_kids() == [jwk.get_kid()]
    with pytest.raises(ValueError):
        storage.delete_keys("../last-key-id")


# rotation by age


def test_rotation_by_max_key_age(jwk, storage):
    first = jwk.get_kid()
    jwt = jwt_for(jwk, max_key_age=DAY)

    jwt.create({"uid": 1}, exp=60)
    assert jwk.get_kid() == first

    with later(DAY + 1):
        jwt.create({"uid": 1}, exp=60)
    assert jwk.get_kid() != first

    retired = WrapJWK(storage)
    retired.load_keys(first)
    assert retired.get_retired() == jwk.get_created()


def test_keys_without_created_rotate_once(storage, tmp_path):
    jwk = WrapJWK(storage)
    jwk.generate_keys()
    jwk.save_keys()
    first = jwk.get_kid()
    data = record(tmp_path, first)
    del data["created"]
    (tmp_path / f"{first}.json").write_text(json.dumps({"data": data}))
    jwt = jwt_for(jwk, max_key_age=DAY)

    jwt.create({"uid": 1}, exp=60)
    second = jwk.get_kid()
    jwt.create({"uid": 1}, exp=60)

    assert second != first
    assert jwk.get_kid() == second


def test_revoked_last_keys_are_not_used(jwk, storage):
    """A revoked last key (e.g. revoked by another tool) is rotated"""
    first = jwk.get_kid()
    storage.update_metadata(first, {"revoked": now()})

    raw = jwt_for(jwk).create({"uid": 1}, exp=60)

    assert jwt_for(jwk).verify(raw).header["kid"] != first


# rotate


def test_rotate_creates_first_keys(storage):
    jwk = WrapJWK(storage)
    jwk.rotate()

    assert storage.get_last_kid() == jwk.get_kid()


def test_rotate_retires_previous_keys(jwk, storage):
    first = jwk.get_kid()
    raw = jwt_for(jwk).create({"uid": 1}, exp=60)

    jwk.rotate()

    assert storage.get_last_kid() == jwk.get_kid() != first
    # tokens signed by the retired keys stay valid
    assert jwt_for(jwk).verify(raw).header["kid"] == first
    old = WrapJWK(storage)
    old.load_keys(first)
    assert old.get_retired() is not None


# revoke


def test_revoke_keys(jwk, storage):
    first = jwk.get_kid()
    raw = jwt_for(jwk).create({"uid": 1}, exp=60)
    jwk.rotate()
    last = jwk.get_kid()

    jwk.revoke(first)

    with pytest.raises(TokenKeyRevokedError):
        jwt_for(jwk).verify(raw)
    assert storage.get_last_kid() == last


def test_revoke_last_keys_generates_new_keys(jwk, storage):
    first = jwk.get_kid()
    raw = jwt_for(jwk).create({"uid": 1}, exp=60)

    jwk.revoke(first)

    assert storage.get_last_kid() != first
    with pytest.raises(TokenKeyRevokedError):
        jwt_for(jwk).verify(raw)
    # creating tokens continues with the new keys
    new = jwt_for(jwk).create({"uid": 1}, exp=60)
    assert jwt_for(jwk).verify(new).header["kid"] == storage.get_last_kid()


def test_revoke_unknown_keys(jwk):
    with pytest.raises(KeysNotFoundError):
        jwk.revoke(uuid.uuid4().hex)


# prune


def test_prune(jwk, storage):
    first = jwk.get_kid()
    jwk.rotate()
    second = jwk.get_kid()
    jwk.rotate()
    last = jwk.get_kid()

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


def test_prune_keeps_keys_without_retired(storage, tmp_path):
    jwk = WrapJWK(storage)
    jwk.generate_keys()
    jwk.save_keys()
    first = jwk.get_kid()
    jwk.generate_keys()
    jwk.save_keys()  # the previous keys are not marked retired

    with later(10 * DAY):
        assert not jwk.prune(max_token_lifetime=3600)
    assert first in storage.list_kids()


def test_prune_revoked_keys(jwk, storage):
    first = jwk.get_kid()
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
    jwk = WrapJWK(LegacyStorage())
    jwk.generate_keys()
    jwk.save_keys()

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

    assert jwt.verify(jwt.create({"uid": 1}, exp=3600))
    with pytest.raises(CreateTokenException, match="max_token_lifetime"):
        jwt.create({"uid": 1}, exp=3601)
    with pytest.raises(CreateTokenException, match="max_token_lifetime"):
        jwt.create({"uid": 1, "exp": now() + 7200})
    with pytest.raises(CreateTokenException, match="required"):
        jwt.create({"uid": 1})


def test_max_token_lifetime_with_default_exp(jwk):
    jwt = jwt_for(jwk, max_token_lifetime=3600, default_exp=600)

    assert jwt.verify(jwt.create({"uid": 1}))
    with pytest.raises(ConfigurationError):
        jwt_for(jwk, max_token_lifetime=600, default_exp=3600)


def test_payload_is_deprecated(jwk):
    with pytest.warns(DeprecationWarning, match="max_key_age"):
        jwt_for(jwk).create({"uid": 1}, exp=60, payload=10)


# list_keys


def test_list_keys(jwk, storage):
    first = jwk.get_kid()
    jwk.rotate()
    jwk.revoke(first)

    keys = jwk.list_keys()

    assert [k["kid"] for k in keys] == [first, storage.get_last_kid()]
    assert keys[0]["retired"] is not None and keys[0]["revoked"] is not None
    assert keys[1]["last"] and keys[1]["retired"] is None
    assert all("private" not in k and "keys" not in k for k in keys)
