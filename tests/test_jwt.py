import time
from unittest.mock import patch

import pytest
from joserfc.errors import BadSignatureError

from joserfc_wrapper import (
    CreateTokenException,
    KeysLoadError,
    ObjectTypeError,
    StorageFile,
    TokenDecodeError,
    TokenKidInvalidError,
    WrapJWK,
    WrapJWT,
)


def test_requires_wrapjwk():
    with pytest.raises(ObjectTypeError):
        WrapJWT(object())  # type: ignore[arg-type]


def test_create_and_decode(jwt, jwk, claims):
    token = jwt.create(claims=dict(claims))
    decoded = jwt.decode(token)

    assert decoded.header == {
        "typ": "JWT",
        "alg": "ES256",
        "kid": jwk.get_kid(),
    }
    assert {k: decoded.claims[k] for k in claims} == claims
    assert isinstance(decoded.claims["iat"], int)
    assert jwt.get_kid() == jwk.get_kid()


def test_create_keeps_custom_claims(jwt, claims):
    token = jwt.create(claims={**claims, "role": "admin"})

    assert jwt.decode(token).claims["role"] == "admin"


@pytest.mark.parametrize("missing", ["iss", "aud", "uid"])
def test_create_missing_claim(jwt, claims, missing):
    del claims[missing]

    with pytest.raises(CreateTokenException, match=missing):
        jwt.create(claims=claims)


@pytest.mark.parametrize(
    "key, value", [("iss", 1), ("aud", None), ("uid", "123"), ("uid", True)]
)
def test_create_wrong_claim_type(jwt, claims, key, value):
    claims[key] = value

    with pytest.raises(CreateTokenException, match=key):
        jwt.create(claims=claims)


def test_create_increases_counter(jwt, storage, claims):
    jwt.create(claims=dict(claims))
    jwt.create(claims=dict(claims))

    loaded = WrapJWK(storage)
    loaded.load_keys()
    assert loaded.get_counter() == 2


def test_create_rotates_keys_by_payload(jwt, jwk, claims):
    first_kid = jwk.get_kid()
    tokens = [jwt.create(claims=dict(claims), payload=2) for _ in range(3)]

    kids = [jwt.decode(t).header["kid"] for t in tokens]
    assert kids[:2] == [first_kid, first_kid]
    assert kids[2] != first_kid
    assert jwk.get_counter() == 1


def test_decode_token_signed_by_older_key(jwt, jwk, claims):
    token = jwt.create(claims=dict(claims))
    jwk.generate_keys()
    jwk.save_keys()

    assert jwt.decode(token).claims["uid"] == claims["uid"]


def test_decode_invalid_kid(jwt, claims):
    token = jwt.create(claims=dict(claims))
    # header with 'kid': 'not-uuid'
    header = "eyJhbGciOiJFUzI1NiIsImtpZCI6Im5vdC11dWlkIn0"
    forged = ".".join([header, *token.split(".")[1:]])

    with pytest.raises(TokenKidInvalidError):
        jwt.decode(forged)


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_validate(jwt, claims):
    token = jwt.decode(jwt.create(claims=dict(claims), exp=60))

    assert jwt.validate(token, {"iss": claims["iss"], "aud": claims["aud"]})


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_validate_missing_claim(jwt, claims):
    token = jwt.decode(jwt.create(claims=dict(claims), exp=60))

    assert not jwt.validate(token, {"role": "admin"})


def test_create_does_not_modify_claims(jwt, claims):
    original = dict(claims)
    jwt.create(claims=claims)

    assert claims == original


def test_decode_uses_public_key(jwt, claims):
    token = jwt.create(claims=dict(claims))

    with patch.object(WrapJWK, "get_private_key", side_effect=AssertionError):
        assert jwt.decode(token).claims["uid"] == claims["uid"]


def test_decode_bad_signature(jwt, claims):
    token = jwt.create(claims=dict(claims))
    other = jwt.create(claims={**claims, "uid": 999})
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


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_validate_wrong_value(jwt, claims):
    token = jwt.decode(jwt.create(claims=dict(claims), exp=60))

    assert not jwt.validate(token, {"iss": "https://other.example.com"})


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_validate_expired(jwt, claims):
    expired = {**claims, "exp": int(time.time()) - 60}
    token = jwt.decode(jwt.create(claims=expired))

    assert not jwt.validate(token, {"iss": claims["iss"]})


def test_decode_unknown_kid(jwt, claims, tmp_path):
    token = jwt.create(claims=dict(claims))
    other = tmp_path / "other"
    other.mkdir()
    storage = StorageFile(str(other))
    other_jwk = WrapJWK(storage)
    other_jwk.generate_keys()
    other_jwk.save_keys()

    with pytest.raises(KeysLoadError):
        WrapJWT(other_jwk).decode(token)


def test_create_without_keys(storage, claims):
    with pytest.raises(KeysLoadError):
        WrapJWT(WrapJWK(storage)).create(claims=claims)


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_create_with_exp(jwt, claims):
    token = jwt.decode(jwt.create(claims=dict(claims), exp=300))

    assert token.claims["exp"] == token.claims["iat"] + 300
    assert jwt.validate(token, {"iss": claims["iss"]})


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_create_with_exp_expired(jwt, claims, monkeypatch):
    token = jwt.create(claims=dict(claims), exp=1)
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now + 120)

    assert not jwt.validate(jwt.decode(token), {"iss": claims["iss"]})


def test_create_without_exp(jwt, claims):
    token = jwt.decode(jwt.create(claims=dict(claims)))

    assert "exp" not in token.claims


@pytest.mark.parametrize("exp", [0, -1, 1.5, "60", True])
def test_create_invalid_exp(jwt, claims, exp):
    with pytest.raises(CreateTokenException, match="positive integer"):
        jwt.create(claims=dict(claims), exp=exp)


def test_create_exp_in_claims_and_parameter(jwt, claims):
    with pytest.raises(CreateTokenException, match="not both"):
        jwt.create(claims={**claims, "exp": int(time.time()) + 60}, exp=60)


def test_create_invalid_exp_does_not_count(jwt, jwk, storage, claims):
    with pytest.raises(CreateTokenException):
        jwt.create(claims=dict(claims), exp=0)

    assert storage.load_keys()[1]["data"]["counter"] == 0


def test_error_message_without_description():
    assert str(TokenDecodeError()) == "Invalid token format."
    assert str(TokenDecodeError("detail")) == "Invalid token format.: detail"


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_validate_token_without_exp(jwt, claims):
    """Since 0.4.0 a token without exp is invalid also in validate"""
    token = jwt.decode(jwt.create(claims=dict(claims)))

    assert not jwt.validate(token, {"iss": claims["iss"]})


def test_validate_is_deprecated(jwt, claims):
    token = jwt.decode(jwt.create(claims=dict(claims), exp=60))

    with pytest.warns(DeprecationWarning, match="use WrapJWT.verify"):
        assert jwt.validate(token, {"iss": claims["iss"]})
