""" joserfc jwk wrapper """
import uuid
from joserfc.jwk import ECKey, OctKey
from joserfc_wrapper.Exceptions import (
    GenerateKeysError,
    ObjectTypeError,
)
from joserfc_wrapper.AbstractKeyStorage import AbstractKeyStorage


class WrapJWK:
    """Handles generation, loading, and saving of private, public keys"""

    def __init__(self, storage: AbstractKeyStorage) -> None:
        """
        :param storage: Storage object
        :type AbstractKeyStorage:
        """
        if not isinstance(storage, AbstractKeyStorage):
            raise ObjectTypeError
        self.__storage = storage

        # unicate key id
        self.__kid: str

        # keys (generated or loaded)
        self.__private: dict
        self.__public: dict

        # key for secret a data (JWE)
        self.__secret_key: dict

        # the number of tokens generated by this key
        self.__counter: int

    def get_kid(self) -> str:
        """Return Key ID"""
        return self.__kid

    def get_public_key(self) -> dict:
        """Return public key"""
        return self.__public

    def get_private_key(self) -> dict:
        """Return private key"""
        return self.__private

    def get_secret_key(self) -> dict:
        """return secret key for encrypted content in claim"""
        return self.__secret_key

    def get_counter(self) -> int:
        """return token counter"""
        return self.__counter

    def increase_counter(self) -> None:
        """Key Counter plus one"""
#        if self.__counter is not None:
        self.__counter += 1

    def generate_keys(self) -> None:
        """
        Generate keys

        :raises GenerateKeysError:
        :returns None:
        """
        try:
            # generate keys
            self.__kid = uuid.uuid4().hex.lower()
            key = ECKey.generate_key("P-256")

            # Save key for encrypted content
            self.__secret_key = OctKey.generate_key(128).as_dict()

            # Save keys for signing
            self.__private = key.as_dict(private=True)
            self.__public = key.as_dict(private=False)

            # New keys have a zero counter
            self.__counter = 0

        except Exception as e:
            raise GenerateKeysError from e

    def save_keys(self) -> None:
        """Save keys"""
        # no 'data' keys here, HC Vault add this key automatically
        keys = {
            "keys": {
                "private": self.__private,
                "public": self.__public,
                "secret": self.__secret_key,
            },
            "counter": self.__counter,
        }
        self.__storage.save_keys(kid=self.__kid, keys=keys)

    def load_keys(self, kid: str = "") -> None:
        """
        Load keys and counter from a storage

        :param kid: Unique key ID, default None
        :type str:
        """
        self.__kid, result = self.__storage.load_keys(kid=kid)

        self.__public = result["data"]["keys"]["public"]
        self.__private = result["data"]["keys"]["private"]
        self.__secret_key = result["data"]["keys"]["secret"]
        self.__counter = result["data"]["counter"]
