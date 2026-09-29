"""Storage interface"""

import threading
import time
from abc import ABC, abstractmethod

from joserfc_wrapper.algorithms import key_algorithm

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
        storage except revoked and unsupported keys, without private keys

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
            if revoked is not None:
                continue
            try:
                algorithm = key_algorithm(public)
            except ValueError:
                # an unsupported key (e.g. RSA in a custom storage)
                continue
            keys.append({**public, "kid": kid, "use": "sig", "alg": algorithm})
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
        Return the last Key ID (the keys which sign new tokens)

        :raises: Any, an error of 'not_found_errors' without keys
        """

    @abstractmethod
    def load_keys(self, kid: str = "") -> tuple[str, dict]:
        """
        Load a key record

        :param kid: Key ID, "" = the last keys ('get_last_kid')
        :returns: Key ID and {"data": key record}
        :raises: Any, an error of 'not_found_errors' for unknown keys
        """

    @abstractmethod
    def save_keys(self, kid: str, keys: dict) -> None:
        """
        Save keys and set them as the last keys

        :param kid: Key ID
        :param keys: the key record
            {"keys": {"private", "public", "secret"}, "created", ...}
        :raises: Any
        """

    @abstractmethod
    def replace_last_keys(self, last_kid: str, kid: str, keys: dict) -> str:
        """
        Atomically save new keys as the last keys (key rotation)

        The new keys are saved only when the last Key ID is still
        'last_kid', so concurrent processes rotate the keys only once. It
        must be atomic (e.g. a lock, check-and-set or a transaction).

        :param last_kid: expected current last Key ID
        :param keys: the key record
            {"keys": {"private", "public", "secret"}, "created", ...}
        :returns: The last Key ID after the operation, 'kid' when the new
            keys were saved, otherwise the Key ID saved by another process
        :raises: Any
        """

    @abstractmethod
    def update_metadata(self, kid: str, metadata: dict) -> None:
        """
        Atomically update metadata fields of a key record

        Metadata are fields of the key record next to 'keys', for example
        'created', 'retired', 'revoked'. It must keep all other fields of
        the record and must not change the last Key ID.

        :param kid: Key ID
        :param metadata: fields to set in the key record
        :raises: Any
        """

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

    @abstractmethod
    def save_last_kid(self, kid: str) -> None:
        """
        Save the last Key ID (the keys which sign new tokens)

        :param kid: Key ID
        :raises: Any
        """
