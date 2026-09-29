import os

import pytest

from joserfc_wrapper import StorageFile, WrapJWK, WrapJWT

CLAIMS = {
    "iss": "https://example.com",
    "aud": "auditor",
    "sub": "123",
    "uid": 123,
}


@pytest.fixture
def claims() -> dict:
    return dict(CLAIMS)


@pytest.fixture
def storage(tmp_path) -> StorageFile:
    return StorageFile(str(tmp_path))


@pytest.fixture
def jwk(storage: StorageFile) -> WrapJWK:
    """WrapJWK with generated and saved keys"""
    wrapjwk = WrapJWK(storage)
    wrapjwk.generate_keys()
    wrapjwk.save_keys()
    return wrapjwk


@pytest.fixture
def jwt(jwk: WrapJWK) -> WrapJWT:
    return WrapJWT(jwk)


def vault_env() -> dict | None:
    """Vault connection from environment (set in docker dev environment)"""
    keys = ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_MOUNT")
    if not all(os.environ.get(k) for k in keys):
        return None
    return {k: os.environ[k] for k in keys}


def redis_url() -> str | None:
    """Redis connection from environment (set in docker dev environment)"""
    return os.environ.get("REDIS_URL") or None


def redis_cluster_url() -> str | None:
    """Redis Cluster connection (docker dev environment)"""
    return os.environ.get("REDIS_CLUSTER_URL") or None
