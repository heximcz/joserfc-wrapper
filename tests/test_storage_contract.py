"""All storages pass the contract checks of joserfc_wrapper.testing"""

import os
import uuid

import fakeredis
import pytest

from joserfc_wrapper import StorageFile, StorageRedis, StorageVault
from joserfc_wrapper.testing import check_storage

from .conftest import redis_cluster_url, redis_url, vault_env
from .test_jwk import MinimalStorage


def test_file(tmp_path):
    check_storage(StorageFile(str(tmp_path)))


def test_redis_fake():
    check_storage(StorageRedis(fakeredis.FakeRedis()))


def test_redis_fake_decoded_responses():
    """A client with decode_responses=True returns str instead of bytes"""
    check_storage(StorageRedis(fakeredis.FakeRedis(decode_responses=True)))


def test_minimal_storage():
    """A custom storage with only the required methods"""
    check_storage(MinimalStorage())


@pytest.mark.vault
def test_vault():
    env = vault_env()
    if env is None:
        pytest.skip("Vault is not configured (VAULT_ADDR, VAULT_TOKEN, ...)")
    check_storage(
        StorageVault(env["VAULT_ADDR"], env["VAULT_TOKEN"], env["VAULT_MOUNT"])
    )


@pytest.mark.redis
def test_redis():
    url = redis_url()
    if url is None:
        pytest.skip("Redis is not configured (REDIS_URL)")
    # own prefix, the checks do not see keys of other tests
    check_storage(StorageRedis.from_url(url, prefix=f"{uuid.uuid4().hex}:"))


@pytest.mark.redis
def test_redis_cluster():
    """Redis Cluster: all keys in one slot by a hash tag in the prefix"""
    url = redis_cluster_url()
    if url is None:
        pytest.skip("Redis Cluster is not configured (REDIS_CLUSTER_URL)")
    import redis  # pylint: disable=import-outside-toplevel

    client = redis.RedisCluster.from_url(url)
    check_storage(StorageRedis(client, prefix=f"{{{uuid.uuid4().hex}}}:"))
