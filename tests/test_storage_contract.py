"""All storages pass the contract checks of joserfc_wrapper.testing"""

import os
import uuid

import fakeredis
import pytest

from joserfc_wrapper import StorageFile, StorageRedis, StorageVault
from joserfc_wrapper.testing import check_storage

from .conftest import redis_url, vault_env
from .test_jwk import LegacyStorage


def test_file(tmp_path):
    check_storage(StorageFile(str(tmp_path)))


def test_redis_fake():
    check_storage(StorageRedis(fakeredis.FakeRedis()))


def test_redis_fake_decoded_responses():
    """A client with decode_responses=True returns str instead of bytes"""
    check_storage(StorageRedis(fakeredis.FakeRedis(decode_responses=True)))


def test_legacy_storage():
    """A custom storage of 0.2.x without atomic methods and listing"""
    check_storage(LegacyStorage(), atomic=False)


@pytest.mark.vault
@pytest.mark.filterwarnings("ignore:KV v1:DeprecationWarning")
@pytest.mark.parametrize("kv_version", [2, 1])
def test_vault(kv_version):
    env = vault_env()
    if env is None:
        pytest.skip("Vault is not configured (VAULT_ADDR, VAULT_TOKEN, ...)")
    mount = env["VAULT_MOUNT"]
    if kv_version == 1:
        mount = os.environ.get("VAULT_MOUNT_V1", "")
        if not mount:
            pytest.skip("KV v1 mount is not configured (VAULT_MOUNT_V1)")
    check_storage(
        StorageVault(
            env["VAULT_ADDR"], env["VAULT_TOKEN"], mount, kv_version=kv_version
        ),
        # KV v1 has no check-and-set, it is not safe for concurrent writes
        atomic=kv_version == 2,
    )


@pytest.mark.redis
def test_redis():
    url = redis_url()
    if url is None:
        pytest.skip("Redis is not configured (REDIS_URL)")
    # own prefix, the checks do not see keys of other tests
    check_storage(StorageRedis.from_url(url, prefix=f"{uuid.uuid4().hex}:"))
