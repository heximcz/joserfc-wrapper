"""Storage interface"""

from abc import ABC, abstractmethod


class AbstractKeyStorage(ABC):
    """Abstract methods for keys storage"""

    #: exceptions of 'load_keys' and 'get_last_kid' meaning that the keys
    #: do not exist in the storage (unknown kid), not a storage failure
    not_found_errors: tuple[type[Exception], ...] = ()

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

        For example:
        def load_keys(self, kid: str):
            if kid == "":
                kid = self.get_last_kid()
            # More logic...

        :param kid: Key ID
        :type kid: str
        :returns: Key ID, Keys (by default last keys)
        :rtype: tuple[str, dict]
        :raises Any:
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
        self.save_keys(
            kid, {"keys": stored["data"]["keys"], "counter": counter}
        )
        # 'save_keys' sets the last Key ID
        if last_kid != kid:
            self._save_last_id(last_kid)
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

    @abstractmethod
    def _save_last_id(self, kid: str) -> None:
        """
        Save last KID

        :param kid:
        :type kid: str
        :returns: None
        """
        pass
