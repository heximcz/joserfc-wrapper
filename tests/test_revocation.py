"""Revocation of single tokens by jti (0.6.0)"""

import time
import uuid
from typing import Any
from unittest.mock import patch

import fakeredis
import pytest

from joserfc_wrapper import (
    ConfigurationError,
    InvalidTokenError,
    KeysLoadError,
    StorageFile,
    StorageRedis,
    TokenClaimError,
    TokenRevokedError,
    TokenSignatureError,
    WrapJWK,
    WrapJWT,
)

from .conftest import key_part, last_kid

from .test_jwk import MinimalStorage

ISS, AUD = "https://example.com", "api"


@pytest.fixture(params=["file", "redis"])
def rstorage(request, tmp_path):
    if request.param == "file":
        return StorageFile(str(tmp_path))
    return StorageRedis(fakeredis.FakeRedis())


@pytest.fixture
def rjwk(rstorage) -> WrapJWK:
    jwk = WrapJWK(rstorage)
    jwk.rotate()
    return jwk


def jwt_for(jwk: WrapJWK, **config) -> WrapJWT:
    return WrapJWT(jwk, issuer=ISS, audience=AUD, revocation=True, **config)


def later(seconds: int):
    return patch("time.time", return_value=time.time() + seconds)


def test_revoke_token(rjwk):
    jwt = jwt_for(rjwk)
    token, other = jwt.create({"sub": "1"}, exp=60), jwt.create(
        {"sub": "2"}, exp=60
    )

    jwt.revoke_token(token)

    with pytest.raises(TokenRevokedError):
        jwt.verify(token)
    assert jwt.verify(other).claims["sub"] == "2"
    # TokenRevokedError is an InvalidTokenError (401)
    with pytest.raises(InvalidTokenError):
        jwt.verify(token)


def test_revoke_jti(rjwk):
    jwt = jwt_for(rjwk)
    token = jwt.create({"sub": "1"}, exp=60)
    claims = jwt.decode(token).claims

    jwt.revoke_jti(claims["jti"], claims["exp"])

    with pytest.raises(TokenRevokedError):
        jwt.verify(token)


def test_verify_without_revocation_ignores_revoked(rjwk):
    token = jwt_for(rjwk).create({"sub": "1"}, exp=60)
    jwt_for(rjwk).revoke_token(token)

    plain = WrapJWT(rjwk, issuer=ISS, audience=AUD)
    assert plain.verify(token).claims["sub"] == "1"


def test_revoked_after_key_rotation(rjwk):
    jwt = jwt_for(rjwk)
    token = jwt.create({"sub": "1"}, exp=60)
    rjwk.rotate()

    jwt.revoke_token(token)

    with pytest.raises(TokenRevokedError):
        jwt.verify(token)


def test_invalid_token_is_not_revoked(rjwk):
    """revoke_token verifies the signature"""
    token = jwt_for(rjwk).create({"sub": "1"}, exp=60)
    header, payload, signature = token.split(".")
    forged = f"{header}.{payload}.{signature[::-1]}"

    with pytest.raises(TokenSignatureError):
        jwt_for(rjwk).revoke_token(forged)


def test_revoke_token_without_exp(rjwk):
    token = WrapJWT(rjwk).create({"iss": ISS, "aud": AUD, "sub": "1"})

    with pytest.raises(TokenClaimError, match="'exp'"):
        jwt_for(rjwk).revoke_token(token)


def test_revoke_expired_token_is_skipped(rjwk, rstorage):
    jwt = jwt_for(rjwk)
    token = jwt.create({"sub": "1"}, exp=60)

    with later(120):
        jwt.revoke_token(token)
    jti = jwt.decode(token).claims["jti"]
    assert not rstorage.is_jti_revoked(jti)


def test_revoked_record_lives_until_exp_and_leeway(rjwk, rstorage):
    jwt = jwt_for(rjwk, leeway=30)
    token = jwt.create({"sub": "1"}, exp=60)
    claims = jwt.decode(token).claims

    with patch.object(
        rstorage, "revoke_jti", wraps=rstorage.revoke_jti
    ) as revoke:
        jwt.revoke_token(token)
    revoke.assert_called_once_with(claims["jti"], claims["exp"] + 30)


def test_prune_deletes_expired_revoked_tokens(tmp_path):
    storage = StorageFile(str(tmp_path))
    jwk = WrapJWK(storage)
    jwk.rotate()
    jwt = jwt_for(jwk, max_token_lifetime=3600)
    token = jwt.create({"sub": "1"}, exp=60)
    jwt.revoke_token(token)
    assert len(list((tmp_path / "revoked").iterdir())) == 1

    jwt.prune()
    assert len(list((tmp_path / "revoked").iterdir())) == 1
    with later(120):
        jwt.prune()
    assert not list((tmp_path / "revoked").iterdir())


def test_token_without_jti(rjwk):
    """Tokens of versions older than 0.4.0 have no jti"""
    jwt = jwt_for(rjwk)
    token = jwt.create({"sub": "1"}, exp=60)
    with patch("uuid.uuid4") as uuid4:
        uuid4.return_value.hex = ""
        no_jti = jwt.create({"sub": "1"}, exp=60)
    assert not jwt.decode(no_jti).claims["jti"]

    assert jwt.verify(no_jti)
    with pytest.raises(TokenClaimError, match="jti"):
        jwt_for(rjwk, require_jti=True).verify(no_jti)
    assert jwt_for(rjwk, require_jti=True).verify(token)


def test_storage_without_revocation():
    jwk = WrapJWK(MinimalStorage())
    jwk.rotate()

    with pytest.raises(ConfigurationError, match="does not support"):
        jwt_for(jwk)


def test_revoke_requires_revocation_enabled(rjwk):
    jwt = WrapJWT(rjwk, issuer=ISS, audience=AUD)
    token = jwt.create({"sub": "1"}, exp=60)

    with pytest.raises(ConfigurationError, match="revocation=True"):
        jwt.revoke_token(token)
    with pytest.raises(ConfigurationError, match="revocation=True"):
        jwt.revoke_jti(uuid.uuid4().hex, int(time.time()) + 60)


@pytest.mark.parametrize("jti, expires_at", [("", 1), ("x", "1"), ("x", True)])
def test_revoke_jti_invalid(rjwk, jti, expires_at):
    with pytest.raises(ValueError):
        jwt_for(rjwk).revoke_jti(jti, expires_at)


@pytest.mark.parametrize("option", ["revocation", "require_jti"])
def test_invalid_options(rjwk, option):
    with pytest.raises(ConfigurationError):
        options: dict[str, Any] = {option: 1}
        WrapJWT(rjwk, **options)


def test_storage_error_is_keys_load_error(rjwk, rstorage):
    jwt = jwt_for(rjwk)
    token = jwt.create({"sub": "1"}, exp=60)

    with patch.object(rstorage, "is_jti_revoked", side_effect=OSError("down")):
        with pytest.raises(KeysLoadError):
            jwt.verify(token)
