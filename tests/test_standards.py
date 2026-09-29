"""Behavior required by the RFCs (audit in 0.9.0), forged tokens"""

import base64
import json
import time
import uuid
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from joserfc import jwe
from joserfc import jwt as joserfc_jwt
from joserfc.errors import JoseError
from joserfc.jwk import ECKey, OctKey, OKPKey

from joserfc_wrapper import (
    ConfigurationError,
    InvalidTokenError,
    StorageJWKS,
    TokenClaimError,
    TokenDecodeError,
    TokenExpiredError,
    TokenSignatureError,
    TokenTypeError,
    WrapJWE,
    WrapJWK,
    WrapJWT,
)
from joserfc_wrapper.token_header import is_valid_kid

from .conftest import key_part, last_kid

ISS, AUD = "https://example.com", "api"
# P-256 group order, a signature (r, s) is also valid as (r, n - s)
ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64json(value) -> str:
    return b64(json.dumps(value, separators=(",", ":")).encode())


def ec_private(jwk: WrapJWK) -> ec.EllipticCurvePrivateKey:
    d = key_part(jwk, "private")["d"]
    value = int.from_bytes(
        base64.urlsafe_b64decode(d + "=" * (-len(d) % 4)), "big"
    )
    return ec.derive_private_key(value, ec.SECP256R1())


def sign(jwk: WrapJWK, header: dict, payload: str) -> str:
    """Sign any header and payload (base64url) by the keys, ES256"""
    signing_input = f"{b64json(header)}.{payload}".encode()
    der = ec_private(jwk).sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{signing_input.decode()}.{b64(signature)}"


@pytest.fixture
def keys(storage) -> WrapJWK:
    jwk = WrapJWK(storage)
    jwk.rotate()
    return jwk


@pytest.fixture
def verifier(keys) -> WrapJWT:
    return WrapJWT(keys, issuer=ISS, audience=AUD)


def claims(**changes) -> dict:
    now = int(time.time())
    return {
        "iss": ISS,
        "aud": AUD,
        "sub": "1",
        "iat": now,
        "exp": now + 60,
        **changes,
    }


def header(keys: WrapJWK, **changes) -> dict:
    return {"alg": "ES256", "kid": last_kid(keys), **changes}


def test_manual_signer_is_valid(keys, verifier):
    assert verifier.verify(sign(keys, header(keys), b64json(claims())))


# algorithms (RFC 8725 3.1, 3.2)


def test_alg_none(keys, verifier):
    token = f"{b64json(header(keys, alg='none'))}.{b64json(claims())}."

    with pytest.raises(InvalidTokenError):
        verifier.verify(token)


def test_alg_hs256_with_the_public_key(keys, verifier):
    """Key confusion: the public key used as an HMAC secret"""
    secret = OctKey.import_key(json.dumps(key_part(keys, "public")).encode())
    token = joserfc_jwt.encode(
        header(keys, alg="HS256"), claims(), secret, algorithms=["HS256"]
    )

    with pytest.raises(InvalidTokenError):
        verifier.verify(token)


def test_other_alg_in_header(keys, verifier):
    token = sign(keys, header(keys), b64json(claims()))
    forged = f"{b64json(header(keys, alg='ES384'))}.{token.split('.', 1)[1]}"

    with pytest.raises(InvalidTokenError):
        verifier.verify(forged)


# header parameters (RFC 7515, 8725bis)


@pytest.mark.parametrize(
    "extra", [{"crit": ["foo"], "foo": 1}, {"crit": ["b64"], "b64": False}]
)
def test_unknown_critical_header(keys, verifier, extra):
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(keys, header(keys, **extra), b64json(claims())))


def test_embedded_jwk_is_ignored(keys, verifier):
    """The key is selected only by kid from the storage"""
    attacker = ECKey.generate_key("P-256")
    token = joserfc_jwt.encode(
        header(keys, jwk=attacker.as_dict(private=False)), claims(), attacker
    )

    with pytest.raises(TokenSignatureError):
        verifier.verify(token)


def test_jku_is_ignored(keys, verifier):
    token = sign(keys, header(keys, jku="https://evil"), b64json(claims()))

    assert verifier.verify(token)


# claims (RFC 7519)


@pytest.mark.parametrize(
    "changes",
    [
        {"exp": "9999999999"},
        {"iat": "x"},
        {"iat": int(time.time()) + 3600},
        {"iss": "https://EXAMPLE.com"},
        {"aud": ["other"]},
        {"aud": []},
        {"sub": 1},
    ],
)
def test_invalid_claims(keys, verifier, changes):
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(keys, header(keys), b64json(claims(**changes))))


def test_exp_expired_true(keys, verifier):
    token = sign(keys, header(keys), b64json(claims(exp=True)))

    with pytest.raises(TokenExpiredError):
        verifier.verify(token)


def test_float_exp_is_valid(keys, verifier):
    """NumericDate may be a non-integer value"""
    token = sign(keys, header(keys), b64json(claims(exp=time.time() + 60.5)))

    assert verifier.verify(token)


@pytest.mark.parametrize("payload", [b"[1, 2]", b'"text"', b"1"])
def test_payload_is_not_an_object(keys, verifier, payload):
    token = sign(keys, header(keys), b64(payload))

    with pytest.raises(TokenDecodeError):
        verifier.verify(token)


def test_duplicate_claims_last_wins(keys, verifier):
    """RFC 7519 allows the lexically last duplicate"""
    exp = int(time.time()) + 60
    payload = (
        f'{{"iss":"https://evil","iss":"{ISS}","aud":"{AUD}",'
        f'"sub":"1","exp":{exp}}}'
    )

    assert verifier.verify(sign(keys, header(keys), b64(payload.encode())))


def test_malleable_ecdsa_signature(keys, verifier):
    """(r, n - s) is also valid: identify tokens by jti, not by the string"""
    token = sign(keys, header(keys), b64json(claims()))
    signing_input, signature = token.rsplit(".", 1)
    raw = base64.urlsafe_b64decode(signature + "==")
    s = int.from_bytes(raw[32:], "big")
    other = f"{signing_input}.{b64(raw[:32] + (ORDER - s).to_bytes(32, 'big'))}"

    assert other != token
    assert verifier.verify(other).claims == verifier.verify(token).claims


def test_revoke_token_with_float_exp(storage, keys):
    jwt = WrapJWT(keys, issuer=ISS, audience=AUD, revocation=True)
    exp = time.time() + 60.5
    token = sign(keys, header(keys), b64json(claims(exp=exp, jti="j1")))

    jwt.revoke_token(token)

    assert storage.is_jti_revoked("j1")
    with pytest.raises(InvalidTokenError):
        jwt.verify(token)


def test_revoke_token_without_numeric_exp(keys):
    jwt = WrapJWT(keys, issuer=ISS, audience=AUD, revocation=True)
    token = sign(keys, header(keys), b64json(claims(exp=True, jti="j1")))

    with pytest.raises(TokenClaimError, match="'exp'"):
        jwt.revoke_token(token)


# JWE (RFC 8725 3.1, 3.6)


def test_jwe_data_of_this_library(keys):
    wrap = WrapJWE(keys)

    assert wrap.decrypt(wrap.encrypt("secret")) == b"secret"


@pytest.mark.parametrize(
    "protected, algorithms",
    [
        ({"alg": "dir", "enc": "A128GCM"}, None),
        ({"alg": "A128KW", "enc": "A256GCM"}, None),
        (
            {"alg": "A128KW", "enc": "A128GCM", "zip": "DEF"},
            ["A128KW", "A128GCM", "DEF"],
        ),
    ],
)
def test_jwe_other_algorithms(keys, protected, algorithms):
    secret = OctKey.import_key(key_part(keys, "secret"))
    data = jwe.encrypt_compact(
        {**protected, "kid": last_kid(keys)},
        b"secret",
        secret,
        algorithms=algorithms,
    )

    with pytest.raises(JoseError):
        WrapJWE(keys).decrypt(data)


# Key ID (RFC 7638 thumbprint, keys of 1.0.0)


def thumbprint(jwk: WrapJWK) -> str:
    public = key_part(jwk, "public")
    members = {k: public[k] for k in ("crv", "kty", "x", "y")}
    digest = hashes.Hash(hashes.SHA256())
    digest.update(json.dumps(members, separators=(",", ":")).encode())
    return b64(digest.finalize())


@pytest.mark.parametrize(
    "kid, valid",
    [
        ("5b0be60b1c91438e9f5c0a6c1b2d3e4f", True),
        ("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", True),
        ("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9X", False),
        ("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs=", False),
        ("../../../etc/passwd-0000000000000000000000", False),
        ("last-key-id", False),
        ("5B0BE60B1C91438E9F5C0A6C1B2D3E4F", False),
    ],
)
def test_kid_formats(kid, valid):
    assert is_valid_kid(kid) is valid


def test_kid_is_rfc7638_thumbprint(keys):
    """Keys created by 1.0.0 have the JWK thumbprint as the Key ID"""
    assert last_kid(keys) == thumbprint(keys)


def test_keys_of_versions_before_1_0(storage, keys):
    """A record of 0.x (uuid Key ID, counter) still loads and verifies"""
    kid = uuid.uuid4().hex
    record = {
        "keys": {
            "private": key_part(keys, "private"),
            "public": key_part(keys, "public"),
            "secret": key_part(keys, "secret"),
        },
        "counter": 7,
    }
    storage.save_keys(kid, record)
    token = sign(keys, {"alg": "ES256", "kid": kid}, b64json(claims()))

    assert WrapJWT(WrapJWK(storage), issuer=ISS, audience=AUD).verify(token)
    assert kid in storage.list_kids()
    assert WrapJWE(keys).decrypt(WrapJWE(keys).encrypt("x", kid=kid)) == b"x"
    jwks = WrapJWK(storage).jwks()
    session = MagicMock()
    session.get.return_value.json.return_value = jwks
    session.get.return_value.url = "https://x/jwks.json"
    remote = WrapJWK(StorageJWKS("https://x/jwks.json", session=session))
    assert WrapJWT(remote, issuer=ISS, audience=AUD).verify(token)


# explicit typing (RFC 8725 3.11, token_type)


def test_token_type(keys):
    access = WrapJWT(keys, issuer=ISS, audience=AUD, token_type="at+jwt")
    refresh = WrapJWT(keys, issuer=ISS, audience=AUD, token_type="refresh+jwt")
    plain = WrapJWT(keys, issuer=ISS, audience=AUD)
    token = access.create({"sub": "1"}, exp=60)

    assert access.decode(token).header["typ"] == "at+jwt"
    assert access.verify(token)
    # a token of one kind cannot be used as another
    with pytest.raises(TokenTypeError, match="refresh"):
        refresh.verify(token)
    with pytest.raises(TokenTypeError):
        access.verify(plain.create({"sub": "1"}, exp=60))
    # without token_type the type is not checked
    assert plain.verify(token)


@pytest.mark.parametrize("configured", ["AT+JWT", "application/at+jwt"])
def test_token_type_is_case_insensitive(keys, configured):
    token = WrapJWT(keys, issuer=ISS, audience=AUD, token_type="at+jwt").create(
        {"sub": "1"}, exp=60
    )

    assert WrapJWT(
        keys, issuer=ISS, audience=AUD, token_type=configured
    ).verify(token)


def test_token_type_missing_header(keys):
    token = sign(keys, header(keys), b64json(claims()))

    with pytest.raises(TokenTypeError):
        WrapJWT(keys, issuer=ISS, audience=AUD, token_type="at+jwt").verify(
            token
        )


@pytest.mark.parametrize("token_type", ["", " ", "application/", 1])
def test_invalid_token_type(keys, token_type):
    with pytest.raises(ConfigurationError):
        WrapJWT(keys, token_type=token_type)


# algorithms of the keys (1.0.0): the algorithm belongs to the key


@pytest.fixture
def ed_keys(storage) -> WrapJWK:
    jwk = WrapJWK(storage)
    jwk.rotate("Ed25519")
    return jwk


def ed_private(jwk: WrapJWK):
    return OKPKey.import_key(key_part(jwk, "private"))


def test_ed25519_token(ed_keys):
    jwt = WrapJWT(ed_keys, issuer=ISS, audience=AUD)
    token = jwt.create({"sub": "1"}, exp=60)

    assert jwt.decode(token).header["alg"] == "Ed25519"
    assert jwt.verify(token)


@pytest.mark.filterwarnings("ignore:EdDSA is deprecated")
def test_eddsa_identifier_is_rejected(ed_keys):
    """Only the fully specified 'Ed25519' (RFC 9864), not 'EdDSA'"""
    token = joserfc_jwt.encode(
        {"alg": "EdDSA", "kid": last_kid(ed_keys)},
        claims(),
        ed_private(ed_keys),
        algorithms=["EdDSA"],
    )

    with pytest.raises(InvalidTokenError):
        WrapJWT(ed_keys, issuer=ISS, audience=AUD).verify(token)


def test_es256_header_with_ed25519_key(ed_keys):
    """The header cannot choose another algorithm than the key has"""
    signed = joserfc_jwt.encode(
        {"alg": "Ed25519", "kid": last_kid(ed_keys)},
        claims(),
        ed_private(ed_keys),
        algorithms=["Ed25519"],
    )
    forged = f"{b64json({'alg': 'ES256', 'kid': last_kid(ed_keys)})}." + (
        signed.split(".", 1)[1]
    )

    with pytest.raises(InvalidTokenError):
        WrapJWT(ed_keys, issuer=ISS, audience=AUD).verify(forged)


def test_ed25519_header_with_es256_key(keys, verifier):
    """A token signed by an attacker's Ed25519 key with kid of an ES256 key"""
    attacker = OKPKey.generate_key("Ed25519")
    token = joserfc_jwt.encode(
        {"alg": "Ed25519", "kid": last_kid(keys)},
        claims(),
        attacker,
        algorithms=["Ed25519"],
    )

    with pytest.raises(InvalidTokenError):
        verifier.verify(token)


def test_hs256_with_ed25519_public_key(ed_keys):
    secret = OctKey.import_key(json.dumps(key_part(ed_keys, "public")).encode())
    token = joserfc_jwt.encode(
        {"alg": "HS256", "kid": last_kid(ed_keys)},
        claims(),
        secret,
        algorithms=["HS256"],
    )

    with pytest.raises(InvalidTokenError):
        WrapJWT(ed_keys, issuer=ISS, audience=AUD).verify(token)


def test_verify_requires_sub(keys, verifier):
    """sub is required by verify since 1.0.0"""
    without = {k: v for k, v in claims().items() if k != "sub"}

    with pytest.raises(TokenClaimError, match="sub"):
        verifier.verify(sign(keys, header(keys), b64json(without)))
    with pytest.raises(TokenClaimError):
        verifier.verify(sign(keys, header(keys), b64json(claims(sub=""))))
