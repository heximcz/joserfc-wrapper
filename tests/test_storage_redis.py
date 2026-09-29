"""StorageRedis with fakeredis (Lua scripts run by lupa)"""

import builtins
import json
import time
import uuid
from unittest.mock import patch

import fakeredis
import pytest

from joserfc_wrapper import (
    AbstractKeyStorage,
    KeysNotFoundError,
    StorageRedis,
    WrapJWK,
)
from joserfc_wrapper.TokenHeader import jti_digest


@pytest.fixture
def client() -> fakeredis.FakeRedis:
    return fakeredis.FakeRedis()


@pytest.fixture
def redis_storage(client) -> StorageRedis:
    return StorageRedis(client, prefix="app:")


def test_is_key_storage(redis_storage):
    assert isinstance(redis_storage, AbstractKeyStorage)
    assert redis_storage.supports_token_revocation()


def test_key_names(redis_storage, client):
    jwk = WrapJWK(redis_storage)
    jwk.rotate()
    kid = jwk.get_kid()
    redis_storage.revoke_jti("jti1", int(time.time()) + 60)

    assert sorted(client.keys()) == sorted(
        [
            f"app:{kid}".encode(),
            b"app:last-key-id",
            f"app:revoked:{jti_digest('jti1')}".encode(),
        ]
    )
    assert json.loads(client.get("app:last-key-id")) == {"kid": kid}
    # the same record format as the other storages (without 'data')
    record = json.loads(client.get(f"app:{kid}"))
    assert set(record) == {"keys", "counter", "created"}


def test_revoked_record_expires(redis_storage, client):
    expires_at = int(time.time()) + 60
    redis_storage.revoke_jti("jti1", expires_at)

    key = f"app:revoked:{jti_digest('jti1')}"
    assert 0 < client.ttl(key) <= 60
    assert redis_storage.prune_revoked(expires_at + 1) == 0


def test_prefix_separates_storages(client):
    first, second = StorageRedis(client, "a:"), StorageRedis(client, "b:")
    WrapJWK(first).rotate()

    assert len(first.list_kids()) == 1
    assert not second.list_kids()
    with pytest.raises(KeysNotFoundError):
        WrapJWK(second).load_keys()


def test_list_kids_escapes_prefix(client):
    """A prefix with glob characters (e.g. a Cluster hash tag)"""
    tagged = StorageRedis(client, "{jwt}[1]:")
    other = StorageRedis(client, "{jwt}1:")
    WrapJWK(tagged).rotate()
    WrapJWK(other).rotate()

    assert tagged.list_kids() == [tagged.get_last_kid()]


def test_list_kids_skips_other_keys(redis_storage, client):
    WrapJWK(redis_storage).rotate()
    client.set("app:something", "x")

    assert redis_storage.list_kids() == [redis_storage.get_last_kid()]


def test_missing_keys(redis_storage):
    with pytest.raises(KeysNotFoundError):
        WrapJWK(redis_storage).load_keys(uuid.uuid4().hex)


def test_increase_counter_missing_keys(redis_storage):
    with pytest.raises(Exception, match="keys not found"):
        redis_storage.increase_counter(uuid.uuid4().hex)


def test_from_url():
    with patch("redis.Redis.from_url") as from_url:
        storage = StorageRedis.from_url(
            "rediss://user:pw@host:6380/2", prefix="x:", socket_timeout=5
        )

    from_url.assert_called_once_with(
        "rediss://user:pw@host:6380/2", socket_timeout=5
    )
    assert storage.prefix == "x:"


def test_redis_not_installed(client):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "redis":
            raise ImportError("No module named 'redis'")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=fake_import):
        with pytest.raises(ImportError, match=r"joserfc-wrapper\[redis\]"):
            StorageRedis(client)
