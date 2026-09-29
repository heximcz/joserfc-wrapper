"""Tests against a running HashiCorp Vault (docker dev environment)"""

import time
from unittest.mock import patch
import uuid

import pytest

from joserfc_wrapper import (
    StorageVault,
    TokenKeyRevokedError,
    WrapJWE,
    WrapJWK,
    WrapJWT,
)

from .conftest import key_part, last_kid, vault_env

pytestmark = pytest.mark.vault


@pytest.fixture
def storage() -> StorageVault:
    env = vault_env()
    if env is None:
        pytest.skip("Vault is not configured (VAULT_ADDR, VAULT_TOKEN, ...)")
    return StorageVault(
        env["VAULT_ADDR"], env["VAULT_TOKEN"], env["VAULT_MOUNT"]
    )


@pytest.mark.parametrize("algorithm", ["ES256", "Ed25519"])
def test_roundtrip(storage, claims, algorithm):
    jwk = WrapJWK(storage)
    kid = jwk.rotate(algorithm)
    jwt = WrapJWT(jwk)

    token = jwt.create(claims=claims)

    assert storage.get_last_kid() == kid == last_kid(jwk)
    assert len(kid) == 43, "RFC 7638 thumbprint"
    assert "counter" not in storage.load_keys(kid)[1]["data"]
    assert jwt.decode(token).header["alg"] == algorithm
    assert jwt.decode(token).claims["sub"] == claims["sub"]
    assert WrapJWE(jwk).decrypt(WrapJWE(jwk).encrypt("x")) == b"x"


def test_keys_of_0x(storage, claims):
    """A record saved by 0.x (uuid Key ID, counter) still verifies"""
    jwk = WrapJWK(storage)
    jwk.rotate()
    data = storage.load_keys()[1]["data"]
    kid = uuid.uuid4().hex
    storage.save_keys(kid, {"keys": data["keys"], "counter": 5})

    assert jwk.load_verification_key(kid)[0] == key_part(jwk, "public", kid)
    assert kid in storage.list_kids()


def test_lifecycle(storage):
    """rotate, list, revoke and prune with a real Vault"""
    jwk = WrapJWK(storage)
    jwk.rotate()
    first = last_kid(jwk)
    jwt = WrapJWT(jwk, issuer="https://example.com", audience="api")
    raw = jwt.create({"sub": "1"}, exp=60)
    jwk.rotate()
    last = last_kid(jwk)

    kids = [key["kid"] for key in jwk.list_keys()]
    assert first in kids and last in kids

    jwk.revoke(first)
    with pytest.raises(TokenKeyRevokedError):
        jwt.verify(raw)

    later = time.time() + 3600 + 2
    with patch("time.time", return_value=later):
        deleted = jwk.prune(max_token_lifetime=3600)
    assert first in deleted
    assert last not in deleted
    assert first not in storage.list_kids()
