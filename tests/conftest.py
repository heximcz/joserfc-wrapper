import os

import pytest

from joserfc_wrapper import StorageFile, WrapJWK, WrapJWT

CLAIMS = {
    "iss": "https://example.com",
    "aud": "auditor",
    "sub": "123",
}


@pytest.fixture
def claims() -> dict:
    return dict(CLAIMS)


@pytest.fixture
def storage(tmp_path) -> StorageFile:
    return StorageFile(str(tmp_path))


@pytest.fixture
def jwk(storage: StorageFile) -> WrapJWK:
    """WrapJWK with the first keys in the storage"""
    wrapjwk = WrapJWK(storage)
    wrapjwk.rotate()
    return wrapjwk


@pytest.fixture
def kid(storage: StorageFile, jwk: WrapJWK) -> str:
    """Key ID of the last keys"""
    return storage.get_last_kid()


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


def last_kid(jwk: WrapJWK) -> str:
    """Key ID of the last keys in the storage of jwk"""
    return jwk.storage.get_last_kid()


def key_record(jwk: WrapJWK, kid: str = "") -> dict:
    """The key record (the 'data' part), default the last keys"""
    return jwk.storage.load_keys(kid)[1]["data"]


def key_part(jwk: WrapJWK, part: str, kid: str = "") -> dict:
    """private, public or secret key (JWK dict), default the last keys"""
    return key_record(jwk, kid)["keys"][part]
