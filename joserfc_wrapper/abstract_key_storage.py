"""Storage interface"""

import threading
import time
from abc import ABC, abstractmethod

#: default lifetime of cached verification keys in seconds
KEY_CACHE_TTL = 300

# creates the cache of a storage instance only once (custom storages do
# not call any __init__ of this class)
_CACHE_INIT_LOCK = threading.Lock()


def check_cache_ttl(ttl: int) -> int:
    """
    :returns: ttl
    :raises ValueError: ttl is not an int >= 0
    """
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 0:
        raise ValueError("'key_cache_ttl' must be an int >= 0 (0 = off).")
    return ttl


class KeyCache:
    """Thread-safe cache of verification keys: kid -> (public key, revoked)"""

    def __init__(self) -> None:
        self.__lock = threading.Lock()
        self.__items: dict[str, tuple[float, tuple[dict, int | None]]] = {}

    def get(self, kid: str, ttl: int) -> tuple[dict, int | None] | None:
        """Return a cached value younger than ttl seconds, or None"""
        with self.__lock:
            item = self.__items.get(kid)
        if item is None or time.monotonic() - item[0] >= ttl:
            return None
        return item[1]

    def set(self, kid: str, value: tuple[dict, int | None]) -> None:
        """Save a value"""
        with self.__lock:
            self.__items[kid] = (time.monotonic(), value)

    def clear(self, kid: str | None = None) -> None:
        """Forget one key, or all keys for None"""
        with self.__lock:
            if kid is None:
                self.__items.clear()
            else:
                self.__items.pop(kid, None)


class AbstractKeyStorage(ABC):
    """Abstract methods for keys storage"""

    #: exceptions of 'load_keys' and 'get_last_kid' meaning that the keys
    #: do not exist in the storage (unknown kid), not a storage failure
    not_found_errors: tuple[type[Exception], ...] = ()

    @property
    def key_cache_ttl(self) -> int:
        """
        Lifetime of cached verification keys in seconds (default 300,
        0 = no cache), see 'load_verification_key'
        """
        return getattr(self, "_key_cache_ttl", KEY_CACHE_TTL)

    @key_cache_ttl.setter
    def key_cache_ttl(self, ttl: int) -> None:
        self._key_cache_ttl = check_cache_ttl(ttl)

    def load_verification_key(self, kid: str) -> tuple[dict, int | None]:
        """
        Return the public key and the time of revocation of a key, used by
        'WrapJWT.verify' and 'decode'

        The result is cached in this storage object for 'key_cache_ttl'
        seconds, verifying tokens then does not read the storage. Share
        one storage object in the application. A revocation by another
        process is visible after 'key_cache_ttl' at the latest. The default
        implementation uses 'load_keys', a storage may override it (e.g.
        StorageJWKS without private keys).

        :param kid: Key ID
        :returns: public key (JWK dict) and revoked (unix timestamp or None)
        :raises: Any, see 'not_found_errors'
        """
        cache = self.__cache()
        ttl = self.key_cache_ttl
        if ttl:
            cached = cache.get(kid, ttl)
            if cached is not None:
                return cached
        _, stored = self.load_keys(kid)
        data = stored["data"]
        value: tuple[dict, int | None] = (
            data["keys"]["public"],
            data.get("revoked"),
        )
        if ttl:
            cache.set(kid, value)
        return value

    def clear_key_cache(self, kid: str | None = None) -> None:
        """
        Forget cached verification keys ('load_verification_key')

        'WrapJWK' calls it after revoking, rotating and deleting keys. Call
        it after changing the keys by other tools.

        :param kid: Key ID, None = all keys
        """
        self.__cache().clear(kid)

    def load_jwks(self) -> dict:
        """
        Return the public keys as a JWK Set (RFC 7517): all keys in the
        storage except revoked keys, without private keys

        The list of keys is always read from the storage (new keys are
        visible immediately), the keys are read by 'load_verification_key'
        (cached). Requires 'list_kids'.

        :returns: {"keys": [JWK, ...]}
        :raises NotImplementedError: the storage does not support listing
        :raises: Any
        """
        keys = []
        for kid in self.list_kids():
            try:
                public, revoked = self.load_verification_key(kid)
            except self.not_found_errors:
                # deleted by 'prune' in the meantime
                continue
            if revoked is None:
                keys.append(
                    {**public, "kid": kid, "use": "sig", "alg": "ES256"}
                )
        return {"keys": keys}

    def __cache(self) -> KeyCache:
        cache = getattr(self, "_key_cache", None)
        if cache is None:
            with _CACHE_INIT_LOCK:
                cache = getattr(self, "_key_cache", None)
                if cache is None:
                    cache = KeyCache()
                    self._key_cache = cache
        return cache

    @abstractmethod
    def get_last_kid(self) -> str:
        """
        Return last Key ID

        :returns: Last Key ID
        :rtype: str
        :raises: Any
        """
        pass

    @abstractmethod
    def load_keys(self, kid: str = "") -> tuple[str, dict]:
        """
        Load keys from a storage

        The implementation of this abstract method should include
        a call methods 'get_last_kid' defined in this class.

        For example::

            def load_keys(self, kid: str):
                if kid == "":
                    kid = self.get_last_kid()
                # More logic...

        :param kid: Key ID
        :type kid: str
        :returns: Key ID, Keys (by default last keys)
        :rtype: tuple[str, dict]
        :raises: Any
        """
        pass

    @abstractmethod
    def save_keys(self, kid: str, keys: dict) -> None:
        """
        Save keys to a storage

        :param kid: - unicate Key ID
        :type kid: str
        :param keys: - { keys: { 'public': dict, 'private': dict } }
        :type keys: dict
        :returns: None
        :raises: Any
        """
        pass

    def increase_counter(self, kid: str, limit: int = 0) -> int | None:
        """
        Atomically increase the counter of signed tokens of a key

        Override it with an atomic implementation to be safe for concurrent
        processes using the same storage. The default implementation uses
        'load_keys' and 'save_keys' and is not atomic. It must not change
        the last Key ID.

        :param kid: Key ID
        :type kid: str
        :param limit: 0 = unlimited, otherwise the counter is not increased
            when it already reached the limit
        :type limit: int
        :returns: New counter value or None when the limit is reached
        :rtype: int | None
        :raises: Any
        """
        last_kid = self.get_last_kid()
        _, stored = self.load_keys(kid)
        counter = stored["data"]["counter"]
        if limit and counter >= limit:
            return None
        counter += 1
        # keep all fields of the record (metadata)
        self.save_keys(kid, {**stored["data"], "counter": counter})
        # 'save_keys' sets the last Key ID
        if last_kid != kid:
            self.save_last_kid(last_kid)
        return counter

    def replace_last_keys(self, last_kid: str, kid: str, keys: dict) -> str:
        """
        Atomically save new keys as the last keys (key rotation)

        The new keys are saved only when the last Key ID is still
        'last_kid', so concurrent processes rotate the keys only once.
        Override it with an atomic implementation, the default
        implementation is not atomic.

        :param last_kid: expected current last Key ID
        :type last_kid: str
        :param kid: Key ID of the new keys
        :type kid: str
        :param keys: - { keys: { 'public': dict, 'private': dict }, ... }
        :type keys: dict
        :returns: The last Key ID after the operation, 'kid' when the new
            keys were saved, otherwise the Key ID saved by another process
        :rtype: str
        :raises: Any
        """
        current = self.get_last_kid()
        if current != last_kid:
            return current
        self.save_keys(kid, keys)
        return kid

    def update_metadata(self, kid: str, metadata: dict) -> None:
        """
        Atomically update metadata fields of a key record

        Metadata are fields of the key record next to 'keys' and 'counter',
        for example 'created', 'retired', 'revoked'. Override it with an
        atomic implementation, the default implementation uses 'load_keys'
        and 'save_keys' and is not atomic. It must not change the last
        Key ID.

        :param kid: Key ID
        :param metadata: fields to set in the key record
        :raises: Any
        """
        last_kid = self.get_last_kid()
        _, stored = self.load_keys(kid)
        self.save_keys(kid, {**stored["data"], **metadata})
        # 'save_keys' sets the last Key ID
        if last_kid != kid:
            self.save_last_kid(last_kid)

    def list_kids(self) -> list[str]:
        """
        Return Key IDs of all keys in the storage

        Required by 'WrapJWK.list_keys' and 'WrapJWK.prune'.

        :returns: Key IDs
        :raises NotImplementedError: the storage does not support it
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support listing keys."
        )

    def revoke_jti(self, jti: str, expires_at: int) -> None:
        """
        Save a revoked token ID until the token expires

        Required by token revocation ('WrapJWT(revocation=True)').

        :param jti: token ID ('jti' claim)
        :param expires_at: 'exp' of the token (unix timestamp), the record
            is not needed after it
        :raises NotImplementedError: the storage does not support it
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support revoking tokens."
        )

    def is_jti_revoked(self, jti: str) -> bool:
        """
        Return True when the token ID is revoked

        Required by token revocation ('WrapJWT(revocation=True)').

        :param jti: token ID ('jti' claim)
        :raises NotImplementedError: the storage does not support it
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support revoking tokens."
        )

    def prune_revoked(self, now: int) -> int:
        """
        Delete records of revoked tokens which expired before 'now'

        Called by 'WrapJWK.prune'. Storages with automatic expiration
        (Redis) return 0.

        :param now: unix timestamp
        :returns: number of deleted records
        :raises NotImplementedError: the storage does not support it
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support revoking tokens."
        )

    def supports_token_revocation(self) -> bool:
        """Return True when the storage implements token revocation"""
        cls = type(self)
        return all(
            getattr(cls, name) is not getattr(AbstractKeyStorage, name)
            for name in ("revoke_jti", "is_jti_revoked", "prune_revoked")
        )

    def delete_keys(self, kid: str) -> None:
        """
        Delete keys from the storage

        Required by 'WrapJWK.prune'. It must not delete the last keys,
        'WrapJWK' never calls it for the last Key ID.

        :param kid: Key ID
        :raises NotImplementedError: the storage does not support it
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support deleting keys."
        )

    def save_last_kid(self, kid: str) -> None:
        """
        Save the last Key ID (the keys which sign new tokens)

        Implement it in a storage (since 0.8.0). The default implementation
        calls '_save_last_id' of storages written for older versions, it
        will be an abstract method in 1.0.0.

        :param kid: Key ID
        :raises NotImplementedError: the storage implements neither
            'save_last_kid' nor '_save_last_id'
        :raises: Any
        """
        if type(self)._save_last_id is AbstractKeyStorage._save_last_id:
            raise NotImplementedError(
                f"{type(self).__name__} must implement 'save_last_kid'."
            )
        self._save_last_id(kid)

    def _save_last_id(self, kid: str) -> None:
        """
        Save the last Key ID, deprecated since 0.8.0 (removed in 1.0.0),
        implement 'save_last_kid'

        :param kid: Key ID
        :raises NotImplementedError: the storage implements neither
        """
        if type(self).save_last_kid is AbstractKeyStorage.save_last_kid:
            raise NotImplementedError(
                f"{type(self).__name__} must implement 'save_last_kid'."
            )
        self.save_last_kid(kid)
