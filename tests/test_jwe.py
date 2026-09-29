import pytest
from joserfc import jwe as joserfc_jwe
from joserfc.jwk import OctKey

from joserfc_wrapper import (
    ObjectTypeError,
    TokenDecodeError,
    TokenKidInvalidError,
    WrapJWE,
)
from joserfc_wrapper.token_header import read_header

from .conftest import key_part, last_kid


def test_requires_wrapjwk():
    with pytest.raises(ObjectTypeError):
        WrapJWE(object())  # type: ignore[arg-type]


@pytest.mark.parametrize("data", ["secret", b"secret"])
def test_encrypt_decrypt(jwk, data):
    jwe = WrapJWE(jwk)
    encrypted = jwe.encrypt(data)

    assert encrypted.count(".") == 4
    assert jwe.decrypt(encrypted) == b"secret"


def test_decrypt_by_kid_after_rotation(jwk):
    jwe = WrapJWE(jwk)
    kid = last_kid(jwk)
    encrypted = jwe.encrypt("secret")
    jwk.rotate()

    assert jwe.decrypt(encrypted, kid=kid) == b"secret"


def test_encrypt_wrong_type(jwk):
    with pytest.raises(TypeError):
        WrapJWE(jwk).encrypt(123)  # type: ignore[arg-type]


def test_decrypt_wrong_type(jwk):
    with pytest.raises(TypeError):
        WrapJWE(jwk).decrypt(b"data")  # type: ignore[arg-type]


def test_header_contains_kid(jwk):
    encrypted = WrapJWE(jwk).encrypt("secret")

    assert read_header(encrypted)["kid"] == last_kid(jwk)


def test_decrypt_after_rotation(jwk):
    jwe = WrapJWE(jwk)
    encrypted = jwe.encrypt("secret")
    jwk.rotate()

    assert jwe.decrypt(encrypted) == b"secret"


def test_decrypt_data_without_kid(jwk):
    """Data encrypted by older versions have no kid in the header"""
    key = OctKey.import_key(key_part(jwk, "secret"))
    protected = {"alg": "A128KW", "enc": "A128GCM"}
    encrypted = joserfc_jwe.encrypt_compact(protected, "secret", key)

    assert WrapJWE(jwk).decrypt(encrypted) == b"secret"


def test_decrypt_malformed(jwk):
    with pytest.raises(TokenDecodeError):
        WrapJWE(jwk).decrypt("not a token")


def test_decrypt_invalid_kid(jwk):
    encrypted = WrapJWE(jwk).encrypt("secret")
    # header {"kid": "../x"}
    forged = ".".join(["eyJraWQiOiAiLi4veCJ9", *encrypted.split(".")[1:]])

    with pytest.raises(TokenKidInvalidError):
        WrapJWE(jwk).decrypt(forged)
