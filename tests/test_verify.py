"""WrapJWT.verify, configuration, jti and get_jti (0.4.0)"""

import time
import uuid
from unittest.mock import patch

import pytest
from hvac.exceptions import InvalidPath, VaultDown

from joserfc_wrapper import (
    ConfigurationError,
    CreateTokenException,
    InvalidTokenError,
    KeysLoadError,
    KeysNotFoundError,
    StorageFile,
    StorageVault,
    TokenClaimError,
    TokenDecodeError,
    TokenExpiredError,
    TokenKidInvalidError,
    TokenKidUnknownError,
    TokenNotYetValidError,
    TokenSignatureError,
    WrapJWK,
    WrapJWT,
)

ISS = "https://example.com"
AUD = "api"


@pytest.fixture
def jwt(jwk) -> WrapJWT:
    """WrapJWT configured for verify"""
    return WrapJWT(jwk, issuer=ISS, audience=AUD, default_exp=300)


def issue(jwt: WrapJWT, **claims) -> str:
    return jwt.create(claims={"uid": 1, **claims})


def now() -> int:
    return int(time.time())


# configuration


@pytest.mark.parametrize(
    "kwargs",
    [
        {"issuer": ""},
        {"issuer": 1},
        {"audience": ""},
        {"audience": []},
        {"audience": ["api", ""]},
        {"audience": 1},
        {"default_exp": 0},
        {"default_exp": -1},
        {"default_exp": True},
        {"default_exp": "60"},
        {"max_age": 0},
        {"leeway": -1},
        {"leeway": 1.5},
    ],
)
def test_invalid_configuration(jwk, kwargs):
    with pytest.raises(ConfigurationError):
        WrapJWT(jwk, **kwargs)


@pytest.mark.parametrize("kwargs", [{}, {"issuer": ISS}, {"audience": AUD}])
def test_verify_requires_issuer_and_audience(jwk, kwargs):
    token = WrapJWT(jwk).create({"iss": ISS, "aud": AUD, "uid": 1}, exp=60)

    with pytest.raises(ConfigurationError):
        WrapJWT(jwk, **kwargs).verify(token)


# verify: valid tokens


def test_verify(jwt):
    token = jwt.verify(issue(jwt, role="admin"))

    assert token.claims["iss"] == ISS
    assert token.claims["aud"] == AUD
    assert token.claims["role"] == "admin"
    assert token.claims["exp"] == token.claims["iat"] + 300


def test_verify_other_claims(jwt):
    raw = issue(jwt, role="admin")

    assert jwt.verify(raw, {"role": "admin"}).claims["uid"] == 1
    with pytest.raises(TokenClaimError):
        jwt.verify(raw, {"role": "user"})


@pytest.mark.parametrize(
    "audience, aud, valid",
    [
        (["api", "admin"], "admin", True),
        (["api", "admin"], ["web", "admin"], True),
        ("api", ["web", "api"], True),
        (["api", "admin"], "web", False),
        ("api", ["web", "cli"], False),
    ],
)
def test_verify_audience(jwk, audience, aud, valid):
    raw = WrapJWT(jwk).create({"iss": ISS, "aud": aud, "uid": 1}, exp=60)
    jwt = WrapJWT(jwk, issuer=ISS, audience=audience)

    if valid:
        assert jwt.verify(raw)
    else:
        with pytest.raises(TokenClaimError):
            jwt.verify(raw)


# verify: invalid tokens


def test_all_errors_are_invalid_token_errors():
    for error in (
        TokenDecodeError,
        TokenKidInvalidError,
        TokenKidUnknownError,
        TokenSignatureError,
        TokenExpiredError,
        TokenNotYetValidError,
        TokenClaimError,
    ):
        assert issubclass(error, InvalidTokenError)


def test_verify_wrong_issuer(jwk, jwt):
    raw = WrapJWT(jwk).create(
        {"iss": "https://other.com", "aud": AUD, "uid": 1}, exp=60
    )

    with pytest.raises(TokenClaimError):
        jwt.verify(raw)


def test_verify_without_exp(jwk, jwt):
    raw = WrapJWT(jwk).create({"iss": ISS, "aud": AUD, "uid": 1})

    with pytest.raises(TokenClaimError, match="exp"):
        jwt.verify(raw)


def test_verify_expired(jwt):
    raw = issue(jwt, exp=now() - 10)

    with pytest.raises(TokenExpiredError):
        jwt.verify(raw)


def test_verify_not_yet_valid(jwt):
    raw = issue(jwt, nbf=now() + 60)

    with pytest.raises(TokenNotYetValidError):
        jwt.verify(raw)


def test_verify_leeway(jwk):
    issuer = WrapJWT(jwk, issuer=ISS, audience=AUD)
    raw = issuer.create({"uid": 1, "exp": now() - 10})

    with pytest.raises(TokenExpiredError):
        issuer.verify(raw)
    assert WrapJWT(jwk, issuer=ISS, audience=AUD, leeway=30).verify(raw)


def test_verify_max_age(jwk, jwt):
    raw = issue(jwt)
    old = WrapJWT(jwk, issuer=ISS, audience=AUD, max_age=60)

    assert old.verify(raw)
    later = now() + 120
    with patch("time.time", return_value=later):
        with pytest.raises(TokenExpiredError, match="max_age"):
            old.verify(raw)


def test_verify_bad_signature(jwt):
    raw = issue(jwt)
    other = issue(jwt, role="admin")
    forged = ".".join([*raw.split(".")[:2], other.split(".")[2]])

    with pytest.raises(TokenSignatureError):
        jwt.verify(forged)


@pytest.mark.parametrize("raw", ["", "abc", "a.b"])
def test_verify_malformed(jwt, raw):
    with pytest.raises(TokenDecodeError):
        jwt.verify(raw)


def test_verify_unknown_kid(jwt, tmp_path):
    raw = issue(jwt)
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    other = WrapJWK(StorageFile(str(other_dir)))
    other.generate_keys()
    other.save_keys()

    with pytest.raises(TokenKidUnknownError):
        WrapJWT(other, issuer=ISS, audience=AUD).verify(raw)


def test_verify_storage_error_is_not_invalid_token(jwt, storage, monkeypatch):
    raw = issue(jwt)

    def broken(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(type(storage), "load_keys", broken)

    with pytest.raises(KeysLoadError) as exc:
        jwt.verify(raw)
    assert not isinstance(exc.value, InvalidTokenError)
    assert not isinstance(exc.value, KeysNotFoundError)


# storage: keys not found


def test_file_storage_keys_not_found(storage):
    with pytest.raises(KeysNotFoundError) as exc:
        WrapJWK(storage).load_keys(uuid.uuid4().hex)

    assert isinstance(exc.value, KeysLoadError)
    assert isinstance(exc.value.__cause__, FileNotFoundError)


@pytest.mark.parametrize(
    "error, expected",
    [(InvalidPath, KeysNotFoundError), (VaultDown, KeysLoadError)],
)
def test_vault_storage_keys_not_found(error, expected):
    with patch("hvac.Client") as client:
        client.return_value.secrets.kv.v2.read_secret_version.side_effect = (
            error()
        )
        jwk = WrapJWK(StorageVault("url", "token", "mount"))

        with pytest.raises(KeysLoadError) as exc:
            jwk.load_keys(uuid.uuid4().hex)

    assert type(exc.value) is expected


# create


def test_create_adds_issuer_and_audience(jwk):
    raw = WrapJWT(jwk, issuer=ISS, audience=["api", "admin"]).create(
        {"uid": 1}, exp=60
    )
    claims = WrapJWT(jwk).decode(raw).claims

    assert claims["iss"] == ISS
    assert claims["aud"] == ["api", "admin"]


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://other.com"},
        {"aud": "web"},
        {"aud": ["api", "web"]},
        {"aud": []},
    ],
)
def test_create_conflict_with_configuration(jwt, claims):
    with pytest.raises(CreateTokenException):
        issue(jwt, **claims)


def test_create_default_exp(jwk):
    raw = WrapJWT(jwk, default_exp=120).create(
        {"iss": ISS, "aud": AUD, "uid": 1}
    )
    claims = WrapJWT(jwk).decode(raw).claims

    assert claims["exp"] == claims["iat"] + 120


def test_create_exp_overrides_default_exp(jwt):
    raw = jwt.create({"uid": 1}, exp=60)
    claims = jwt.verify(raw).claims

    assert claims["exp"] == claims["iat"] + 60


def test_create_without_default_exp_has_no_exp(jwk):
    raw = WrapJWT(jwk).create({"iss": ISS, "aud": AUD, "uid": 1})

    assert "exp" not in WrapJWT(jwk).decode(raw).claims


# jti


def test_create_adds_jti(jwt):
    first = jwt.verify(issue(jwt)).claims["jti"]
    second = jwt.verify(issue(jwt)).claims["jti"]

    assert first != second
    assert uuid.UUID(first).version == 4
    assert first == uuid.UUID(first).hex


def test_create_keeps_custom_jti(jwt):
    assert jwt.verify(issue(jwt, jti="my-id")).claims["jti"] == "my-id"


@pytest.mark.parametrize("jti", ["", 1, None])
def test_create_invalid_jti(jwt, jti):
    with pytest.raises(CreateTokenException, match="jti"):
        issue(jwt, jti=jti)


def test_get_jti(jwt):
    raw = issue(jwt)

    assert jwt.get_jti(raw) == jwt.verify(raw).claims["jti"]


def test_get_jti_verifies_signature(jwt):
    raw = issue(jwt)
    other = issue(jwt, role="admin")
    forged = ".".join([*raw.split(".")[:2], other.split(".")[2]])

    with pytest.raises(Exception) as exc:
        jwt.get_jti(forged)
    assert "signature" in type(exc.value).__name__.lower()
