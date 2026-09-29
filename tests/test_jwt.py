import time
from unittest.mock import patch

import pytest
from joserfc.errors import BadSignatureError

from joserfc_wrapper import (
    CreateTokenError,
    KeysLoadError,
    ObjectTypeError,
    StorageFile,
    TokenDecodeError,
    TokenKidInvalidError,
    WrapJWK,
    WrapJWT,
)

from .conftest import last_kid


def test_requires_wrapjwk():
    with pytest.raises(ObjectTypeError):
        WrapJWT(object())  # type: ignore[arg-type]


def test_create_and_decode(jwt, jwk, claims):
    token = jwt.create(claims=dict(claims))
    decoded = jwt.decode(token)

    assert decoded.header == {
        "typ": "JWT",
        "alg": "ES256",
        "kid": last_kid(jwk),
    }
    assert {k: decoded.claims[k] for k in claims} == claims
    assert isinstance(decoded.claims["iat"], int)
    assert not hasattr(jwt, "get_kid"), "removed in 1.0.0"


def test_create_ed25519(jwt, jwk, claims):
    jwk.rotate("Ed25519")

    decoded = jwt.decode(jwt.create(claims=dict(claims)))

    assert decoded.header["alg"] == "Ed25519"
    assert decoded.header["kid"] == last_kid(jwk)


def test_create_keeps_custom_claims(jwt, claims):
    token = jwt.create(claims={**claims, "role": "admin", "uid": 1})

    claims = jwt.decode(token).claims
    assert claims["role"] == "admin" and claims["uid"] == 1


@pytest.mark.parametrize("missing", ["iss", "aud", "sub"])
def test_create_missing_claim(jwt, claims, missing):
    del claims[missing]

    with pytest.raises(CreateTokenError, match=missing):
        jwt.create(claims=claims)


@pytest.mark.parametrize(
    "key, value",
    [("iss", 1), ("aud", None), ("sub", 123), ("sub", ""), ("sub", None)],
)
def test_create_wrong_claim_type(jwt, claims, key, value):
    claims[key] = value

    with pytest.raises(CreateTokenError, match=key):
        jwt.create(claims=claims)


def test_uid_is_a_custom_claim(jwt, claims):
    """Any type since 1.0.0, 'sub' identifies the subject"""
    token = jwt.create(claims={**claims, "uid": "abc"})

    assert jwt.decode(token).claims["uid"] == "abc"


def test_create_without_payload_parameter(jwt, claims):
    with pytest.raises(TypeError):
        jwt.create(dict(claims), payload=2)  # type: ignore[call-arg]


def test_decode_token_signed_by_older_key(jwt, jwk, claims):
    token = jwt.create(claims=dict(claims))
    jwk.rotate()

    assert jwt.decode(token).claims["sub"] == claims["sub"]


def test_decode_invalid_kid(jwt, claims):
    token = jwt.create(claims=dict(claims))
    # header with 'kid': 'not-uuid'
    header = "eyJhbGciOiJFUzI1NiIsImtpZCI6Im5vdC11dWlkIn0"
    forged = ".".join([header, *token.split(".")[1:]])

    with pytest.raises(TokenKidInvalidError):
        jwt.decode(forged)


def test_create_does_not_modify_claims(jwt, claims):
    original = dict(claims)
    jwt.create(claims=claims)

    assert claims == original


def test_decode_reads_only_the_public_key(jwt, storage, claims):
    token = jwt.create(claims=dict(claims))

    with patch.object(storage, "load_keys", wraps=storage.load_keys) as load:
        jwt.decode(token)
    # the verification key is cached since the storage was used by create
    assert load.call_count <= 1


def test_decode_bad_signature(jwt, claims):
    token = jwt.create(claims=dict(claims))
    other = jwt.create(claims={**claims, "sub": "999"})
    forged = ".".join([*token.split(".")[:2], other.split(".")[2]])

    with pytest.raises(BadSignatureError):
        jwt.decode(forged)


@pytest.mark.parametrize("token", ["", "abc", "a.b", "!!!.b.c", "WzFd.b.c"])
def test_decode_malformed(jwt, token):
    with pytest.raises(TokenDecodeError):
        jwt.decode(token)


def test_decode_missing_kid(jwt, claims):
    token = jwt.create(claims=dict(claims))
    # header {"alg": "ES256"}
    forged = ".".join(["eyJhbGciOiJFUzI1NiJ9", *token.split(".")[1:]])

    with pytest.raises(TokenKidInvalidError):
        jwt.decode(forged)


def test_decode_unknown_kid(jwt, claims, tmp_path):
    token = jwt.create(claims=dict(claims))
    other = tmp_path / "other"
    other.mkdir()
    other_jwk = WrapJWK(StorageFile(str(other)))
    other_jwk.rotate()

    with pytest.raises(KeysLoadError):
        WrapJWT(other_jwk).decode(token)


def test_create_without_keys(storage, claims):
    with pytest.raises(KeysLoadError):
        WrapJWT(WrapJWK(storage)).create(claims=claims)


def test_create_with_exp(jwt, claims):
    token = jwt.decode(jwt.create(claims=dict(claims), exp=300))

    assert token.claims["exp"] == token.claims["iat"] + 300


def test_create_without_exp(jwt, claims):
    token = jwt.decode(jwt.create(claims=dict(claims)))

    assert "exp" not in token.claims


@pytest.mark.parametrize("exp", [0, -1, 1.5, "60", True])
def test_create_invalid_exp(jwt, claims, exp):
    with pytest.raises(CreateTokenError, match="positive integer"):
        jwt.create(claims=dict(claims), exp=exp)


def test_create_exp_in_claims_and_parameter(jwt, claims):
    with pytest.raises(CreateTokenError, match="not both"):
        jwt.create(claims={**claims, "exp": int(time.time()) + 60}, exp=60)


def test_error_message_without_description():
    assert str(TokenDecodeError()) == "Invalid token format."
    assert str(TokenDecodeError("detail")) == "Invalid token format.: detail"
