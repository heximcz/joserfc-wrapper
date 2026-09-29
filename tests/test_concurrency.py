"""Concurrent processes signing tokens with the same storage"""

import json
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

# payload is deprecated, but still supported and tested
pytestmark = pytest.mark.filterwarnings(
    "ignore:.payload. is deprecated:DeprecationWarning"
)

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
    factory, location, payload = args
    jwt = WrapJWT(WrapJWK(factory(location)))
    tokens = [jwt.create(dict(CLAIMS), payload=payload) for _ in range(TOKENS)]
    return [jwt.decode(t).header["kid"] for t in tokens]


def run(factory, location: str, payload: int) -> list[str]:
    """Sign tokens in parallel processes, return KID of each token"""
    jwk = WrapJWK(factory(location))
    jwk.generate_keys()
    jwk.save_keys()
    with get_context("spawn").Pool(PROCESSES) as pool:
        results = pool.map(sign, [(factory, location, payload)] * PROCESSES)
    return [kid for kids in results for kid in kids]


def counters(storage, kids: list[str]) -> dict[str, int]:
    return {
        kid: storage.load_keys(kid)[1]["data"]["counter"] for kid in set(kids)
    }


def assert_counted(storage, kids: list[str], payload: int) -> None:
    total = PROCESSES * TOKENS
    assert len(kids) == total
    counted = counters(storage, kids)
    # every token is counted by the key which signed it
    assert counted == {kid: kids.count(kid) for kid in counted}
    if payload:
        assert max(counted.values()) <= payload
        assert len(counted) == -(-total // payload)
    else:
        assert len(counted) == 1


@pytest.mark.parametrize("payload", [0, 7])
def test_storage_file(tmp_path, payload):
    kids = run(storage_file, str(tmp_path), payload)

    assert_counted(StorageFile(str(tmp_path)), kids, payload)
    assert (
        json.loads((tmp_path / "last-key-id.json").read_text())["kid"] in kids
    )


@pytest.mark.vault
@pytest.mark.parametrize("payload", [0, 7])
def test_storage_vault(payload):
    env = vault_env()
    if env is None:
        pytest.skip("Vault is not configured (VAULT_ADDR, VAULT_TOKEN, ...)")
    mount = env["VAULT_MOUNT"]
    kids = run(storage_vault, mount, payload)

    assert_counted(storage_vault(mount), kids, payload)


@pytest.mark.redis
@pytest.mark.parametrize("payload", [0, 7])
def test_storage_redis(payload):
    if redis_url() is None:
        pytest.skip("Redis is not configured (REDIS_URL)")
    prefix = f"{uuid.uuid4().hex}:"
    kids = run(storage_redis, prefix, payload)

    assert_counted(storage_redis(prefix), kids, payload)
