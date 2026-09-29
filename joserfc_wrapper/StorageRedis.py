"""redis manipulation class"""

import json
import re
from typing import Any

from joserfc_wrapper.AbstractKeyStorage import AbstractKeyStorage, KEY_CACHE_TTL
from joserfc_wrapper.TokenHeader import is_valid_kid, jti_digest

# the key record is changed by Lua scripts, Redis runs a script atomically
# (no other command runs in the meantime), safe for concurrent processes

INCREASE_COUNTER = """
local data = redis.call("GET", KEYS[1])
if not data then
    return redis.error_reply("keys not found")
end
local record = cjson.decode(data)
local limit = tonumber(ARGV[1])
if limit > 0 and record.counter >= limit then
    return false
end
record.counter = record.counter + 1
redis.call("SET", KEYS[1], cjson.encode(record))
return record.counter
"""

REPLACE_LAST_KEYS = """
local data = redis.call("GET", KEYS[1])
if data then
    local current = cjson.decode(data).kid
    if current ~= ARGV[1] then
        return current
    end
end
redis.call("SET", KEYS[2], ARGV[3])
redis.call("SET", KEYS[1], cjson.encode({kid = ARGV[2]}))
return ARGV[2]
"""

UPDATE_METADATA = """
local data = redis.call("GET", KEYS[1])
if not data then
    return redis.error_reply("keys not found")
end
local record = cjson.decode(data)
for field, value in pairs(cjson.decode(ARGV[1])) do
    record[field] = value
end
redis.call("SET", KEYS[1], cjson.encode(record))
return 1
"""


class RedisKeyNotFoundError(LookupError):
    """The key does not exist in Redis"""


class StorageRedis(AbstractKeyStorage):
    """
    Interface for saving and loading keys in Redis (6.2 or newer)

    Requires the extra dependency: pip install joserfc-wrapper[redis]

    Redis must persist the data (AOF or RDB), otherwise the keys are lost
    after a restart and all tokens become invalid. For Redis Cluster use a
    prefix with a hash tag, e.g. "{jwt}:", all keys must be in one slot.
    """

    not_found_errors = (RedisKeyNotFoundError,)

    def __init__(
        self,
        client: Any,
        prefix: str = "jwt:",
        key_cache_ttl: int = KEY_CACHE_TTL,
    ) -> None:
        """
        :param client: configured client, e.g. redis.Redis(host=..., port=...,
            password=..., ssl=...) or redis.Redis.from_url(...)
        :param prefix: prefix of all keys, for a shared Redis
        :param key_cache_ttl: lifetime of cached verification keys in
            seconds (default 300, 0 = no cache), see
            'AbstractKeyStorage.load_verification_key'
        :raises ImportError: redis-py is not installed
        :raises ValueError: invalid key_cache_ttl
        """
        self.key_cache_ttl = key_cache_ttl
        self.__import_redis()
        self.__client = client
        self.prefix = prefix
        # scripts are registered once, redis-py sends them by SHA
        self.__increase_counter = client.register_script(INCREASE_COUNTER)
        self.__replace_last_keys = client.register_script(REPLACE_LAST_KEYS)
        self.__update_metadata = client.register_script(UPDATE_METADATA)

    @classmethod
    def from_url(
        cls,
        url: str,
        prefix: str = "jwt:",
        key_cache_ttl: int = KEY_CACHE_TTL,
        **options: Any,
    ) -> "StorageRedis":
        """
        Create the storage from a URL

        :param url: redis://[[user]:password@]host[:port][/db], rediss:// for
            TLS, unix:///path/to/socket
        :param prefix: prefix of all keys
        :param key_cache_ttl: lifetime of cached verification keys in
            seconds (default 300, 0 = no cache)
        :param options: other options of redis.Redis (socket_timeout,
            ssl_ca_certs, health_check_interval, ...)
        :raises ImportError: redis-py is not installed
        """
        redis = cls.__import_redis()
        return cls(
            redis.Redis.from_url(url, **options),
            prefix=prefix,
            key_cache_ttl=key_cache_ttl,
        )

    def get_last_kid(self) -> str:
        """Return last Key ID"""
        return self.__get_json(self.__key("last-key-id"))["kid"]

    def load_keys(self, kid: str = "") -> tuple[str, dict]:
        """Load keys"""
        if kid == "":
            kid = self.get_last_kid()
        return kid, {"data": self.__get_json(self.__key(kid))}

    def save_keys(self, kid: str, keys: dict) -> None:
        """Save keys and set them as the last keys (one transaction)"""
        pipe = self.__client.pipeline(transaction=True)
        pipe.set(self.__key(kid), json.dumps(keys))
        pipe.set(self.__key("last-key-id"), json.dumps({"kid": kid}))
        pipe.execute()

    def increase_counter(self, kid: str, limit: int = 0) -> int | None:
        """Atomically increase the counter of signed tokens of a key"""
        result = self.__increase_counter(keys=[self.__key(kid)], args=[limit])
        return None if result is None else int(result)

    def replace_last_keys(self, last_kid: str, kid: str, keys: dict) -> str:
        """Atomically save new keys as the last keys (key rotation)"""
        result = self.__replace_last_keys(
            keys=[self.__key("last-key-id"), self.__key(kid)],
            args=[last_kid, kid, json.dumps(keys)],
        )
        return result.decode() if isinstance(result, bytes) else result

    def update_metadata(self, kid: str, metadata: dict) -> None:
        """Atomically update metadata fields of a key record"""
        self.__update_metadata(
            keys=[self.__key(kid)], args=[json.dumps(metadata)]
        )

    def list_kids(self) -> list[str]:
        """Return Key IDs of all keys in the storage"""
        pattern = re.sub(r"([*?\[\]\\])", r"\\\1", self.prefix) + "*"
        kids = []
        for key in self.__client.scan_iter(match=pattern, count=500):
            name = key.decode() if isinstance(key, bytes) else key
            kid = name[len(self.prefix) :]
            if is_valid_kid(kid):
                kids.append(kid)
        return sorted(kids)

    def delete_keys(self, kid: str) -> None:
        """Delete keys from the storage"""
        if not is_valid_kid(kid):
            raise ValueError(f"Invalid Key ID '{kid}'.")
        self.__client.delete(self.__key(kid))

    def revoke_jti(self, jti: str, expires_at: int) -> None:
        """Save a revoked token ID, Redis deletes it when the token expires"""
        self.__client.set(
            self.__key(f"revoked:{jti_digest(jti)}"), "1", exat=expires_at
        )

    def is_jti_revoked(self, jti: str) -> bool:
        """Return True when the token ID is revoked"""
        return bool(
            self.__client.exists(self.__key(f"revoked:{jti_digest(jti)}"))
        )

    def prune_revoked(self, now: int) -> int:
        """Nothing to delete, Redis deletes expired records itself"""
        return 0

    def _save_last_id(self, kid: str) -> None:
        """Save last Key ID"""
        self.__client.set(self.__key("last-key-id"), json.dumps({"kid": kid}))

    def __key(self, name: str) -> str:
        return f"{self.prefix}{name}"

    def __get_json(self, key: str) -> dict:
        data = self.__client.get(key)
        if data is None:
            raise RedisKeyNotFoundError(f"Key '{key}' not found in Redis.")
        return json.loads(data)

    @staticmethod
    def __import_redis() -> Any:
        try:
            import redis  # pylint: disable=import-outside-toplevel
        except ImportError as e:
            raise ImportError(
                "StorageRedis requires redis-py: "
                "pip install joserfc-wrapper[redis]"
            ) from e
        return redis
