"""Concurrent processes signing tokens with the same storage"""

import time
import uuid
from multiprocessing import get_context

import pytest

from joserfc_wrapper import (
    StorageFile,
    StorageRedis,
    StorageVault,
    WrapJWK,
    WrapJWT,
)

from .conftest import CLAIMS, redis_url, vault_env

PROCESSES = 6
TOKENS = 20


def storage_file(cert_dir: str) -> StorageFile:
    return StorageFile(cert_dir)


def storage_vault(mount: str) -> StorageVault:
    env = vault_env()
    assert env is not None
    return StorageVault(env["VAULT_ADDR"], env["VAULT_TOKEN"], mount)


def storage_redis(prefix: str) -> StorageRedis:
    url = redis_url()
    assert url is not None
    return StorageRedis.from_url(url, prefix=prefix)


def sign(args: tuple) -> list[str]:
    factory, location = args
    jwt = WrapJWT(WrapJWK(factory(location)))
    tokens = [jwt.create(dict(CLAIMS), exp=60) for _ in range(TOKENS)]
    return [jwt.decode(t).header["kid"] for t in tokens]


def run(factory, location: str) -> tuple[str, list[str]]:
    """
    Revoke the last keys and sign tokens in parallel processes, every
    process has to rotate the keys first

    :returns: the revoked Key ID, Key IDs of the tokens
    """
    storage = factory(location)
    WrapJWK(storage).rotate()
    revoked = storage.get_last_kid()
    storage.update_metadata(revoked, {"revoked": int(time.time())})
    with get_context("spawn").Pool(PROCESSES) as pool:
        results = pool.map(sign, [(factory, location)] * PROCESSES)
    return revoked, [kid for kids in results for kid in kids]


def assert_rotated_once(storage, revoked: str, kids: list[str]) -> None:
    assert len(kids) == PROCESSES * TOKENS
    # all processes use the keys of one rotation
    assert len(set(kids)) == 1
    assert kids[0] != revoked
    assert storage.get_last_kid() == kids[0]


def test_storage_file(tmp_path):
    revoked, kids = run(storage_file, str(tmp_path))

    storage = StorageFile(str(tmp_path))
    assert_rotated_once(storage, revoked, kids)
    assert sorted(storage.list_kids()) == sorted([revoked, kids[0]])


@pytest.mark.vault
def test_storage_vault():
    env = vault_env()
    if env is None:
        pytest.skip("Vault is not configured (VAULT_ADDR, VAULT_TOKEN, ...)")
    mount = env["VAULT_MOUNT"]
    revoked, kids = run(storage_vault, mount)

    assert_rotated_once(storage_vault(mount), revoked, kids)


@pytest.mark.redis
def test_storage_redis():
    if redis_url() is None:
        pytest.skip("Redis is not configured (REDIS_URL)")
    prefix = f"{uuid.uuid4().hex}:"
    revoked, kids = run(storage_redis, prefix)

    storage = storage_redis(prefix)
    assert_rotated_once(storage, revoked, kids)
    assert sorted(storage.list_kids()) == sorted([revoked, kids[0]])
