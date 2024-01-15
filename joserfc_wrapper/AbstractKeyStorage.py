from abc import ABC, abstractmethod


class AbstractKeyStorage(ABC):
    """
    Abstract for keys storage
    """

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
    def load_keys(self, kid: str = None) -> tuple[str, dict]:
        """
        Load keys from a storage

        The implementation of this abstract method should include a call methods 'get_last_kid' defined in this class.

        For example:
        def load_keys(self, kid: str):
            if not kid:
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
