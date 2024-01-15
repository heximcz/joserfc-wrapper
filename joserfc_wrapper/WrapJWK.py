import uuid
from joserfc.jwk import ECKey
from joserfc_wrapper.exceptions import (
    GenerateKeysError,
    StorageObjectError,
    KeysNotGenerated,
)
from joserfc_wrapper import StorageVault, AbstractKeyStorage

# TODO: add jwe 
# TODO: add future count param to keys for jwt generatet with this key

class WrapJWK:
    def __init__(self, storage: AbstractKeyStorage = StorageVault()) -> None:
        """
        Handles generation, loading, and saving of private and public keys.

        :param storage: Storage object
        :type AbstractKeyStorage:
        """
        # unicate key id
        self.__kid = None

        # define storage manager
        if not isinstance(storage, AbstractKeyStorage):
            raise StorageObjectError
        self.__storage = storage

        # True = keys generated but not saved
        self.__generated = False

        # keys (generated or loaded)
        self.__private: dict = None
        self.__public: dict = None

    def get_kid(self) -> str | None:
        """Return Key ID"""
        return self.__kid

    def get_public_key(self) -> dict | None:
        """Return public key"""
        return self.__public

    def get_private_key(self) -> dict | None:
        """Return private key"""
        return self.__private

    def generate_keys(self) -> None:
        """
        Generate keys
        
        :raises GenerateKeysError:
        :returns None:
        """
        try:
            self.__kid = uuid.uuid4().hex.lower()
            key = ECKey.generate_key("P-256")

            # Save keys inside model
            self.__private = key.as_dict(private=True)
            self.__public = key.as_dict(private=False)
            self.__generated = True
        except Exception:
            raise GenerateKeysError

    def save_keys(self):
        """Save keys"""
        if not self.__generated:
            raise KeysNotGenerated
        keys = {"keys": {"private": self.__private, "public": self.__public}}
        self.__storage.save_keys(kid=self.__kid, keys=keys)
        self.__generated = False

    def load_keys(self, kid: str = None):
        """Load keys"""
        self.__kid, result = self.__storage.load_keys(kid=kid)
        self.__public = result["data"]["keys"]["public"]
        self.__private = result["data"]["keys"]["private"]
        self.__generated = False
