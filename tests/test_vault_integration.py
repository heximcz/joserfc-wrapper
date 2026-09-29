"""Tests against a running HashiCorp Vault (docker dev environment)"""

import os
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

from .conftest import vault_env

pytestmark = [
    pytest.mark.vault,
    # KV v1 is deprecated, but still supported and tested
    pytest.mark.filterwarnings("ignore:KV v1:DeprecationWarning"),
]


@pytest.fixture(params=[2, 1], ids=["kv2", "kv1"])
def storage(request) -> StorageVault:
    env = vault_env()
    if env is None:
        pytest.skip("Vault is not configured (VAULT_ADDR, VAULT_TOKEN, ...)")
    mount = env["VAULT_MOUNT"]
    if request.param == 1:
        mount = os.environ.get("VAULT_MOUNT_V1", "")
        if not mount:
            pytest.skip("KV v1 mount is not configured (VAULT_MOUNT_V1)")
    return StorageVault(
        env["VAULT_ADDR"], env["VAULT_TOKEN"], mount, kv_version=request.param
    )


def test_roundtrip(storage, claims):
    jwk = WrapJWK(storage)
    jwk.generate_keys()
    jwk.save_keys()
    jwt = WrapJWT(jwk)

    token = jwt.create(claims=claims)

    assert storage.get_last_kid() == jwk.get_kid()
    assert uuid.UUID(jwk.get_kid()).version == 4
    assert jwt.decode(token).claims["uid"] == claims["uid"]
    assert WrapJWE(jwk).decrypt(WrapJWE(jwk).encrypt("x")) == b"x"


@pytest.mark.filterwarnings("ignore:.payload. is deprecated:DeprecationWarning")
def test_counter_and_rotation(storage, claims):
    jwk = WrapJWK(storage)
    jwk.generate_keys()
    jwk.save_keys()
    first = jwk.get_kid()
    jwt = WrapJWT(jwk)

    for _ in range(3):
        jwt.create(claims=dict(claims), payload=2)

    assert storage.load_keys(first)[1]["data"]["counter"] == 2
    assert storage.get_last_kid() == jwk.get_kid() != first
    assert storage.load_keys()[1]["data"]["counter"] == 1


def test_lifecycle(storage):
    """rotate, list, revoke and prune with a real Vault"""
    jwk = WrapJWK(storage)
    jwk.rotate()
    first = jwk.get_kid()
    jwt = WrapJWT(jwk, issuer="https://example.com", audience="api")
    raw = jwt.create({"uid": 1}, exp=60)
    jwk.rotate()
    last = jwk.get_kid()

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
