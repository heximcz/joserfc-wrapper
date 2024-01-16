import uuid
from joserfc.jwk import ECKey, OctKey
from joserfc_wrapper.exceptions import (
    GenerateKeysError,
    ObjectTypeError,
    KeysNotGenerated,
)
from joserfc_wrapper import StorageVault, AbstractKeyStorage


class WrapJWK:
    def __init__(self, storage: AbstractKeyStorage = StorageVault()) -> None:
        """
        Handles generation, loading, and saving of private, public keys

        :param storage: Storage object
        :type AbstractKeyStorage:
        """
        # define storage manager
        if not isinstance(storage, AbstractKeyStorage):
            raise ObjectTypeError
        self.__storage = storage

        # unicate key id
        self.__kid = None

        # True = keys generated or loaded
        self.__generated = False

        # keys (generated or loaded)
        self.__private: dict = None
        self.__public: dict = None

        # key for secret a data (JWE)
        self.__secret_key = None

        # how many tokens were generated with the help of this certificate
        self.__counter = None

    def get_kid(self) -> str | None:
        """Return Key ID"""
        return self.__kid

    def get_public_key(self) -> dict | None:
        """Return public key"""
        return self.__public

    def get_private_key(self) -> dict | None:
        """Return private key"""
        return self.__private
    
    def get_secret_key(self) -> dict | None:
        """return secret key for encrypted content in claim"""
        return self.__secret_key

    def get_counter(self) -> dict | None:
        """return token counter"""
        return self.__counter
    
    # def set_counter(self, counter: int) -> None:
    #     self.__counter = counter

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

            self.__generated = True
        except Exception:
            raise GenerateKeysError

    def save_keys(self):
        """Save keys"""
        if not self.__generated:
            raise KeysNotGenerated
        
        # no 'data' keys here, HC Vault add this key automatically
        keys = {
            "keys": {
                "private": self.__private,
                "public": self.__public,
                "secret": self.__secret_key,
            },
            "counter": self.__counter
        }
        self.__storage.save_keys(kid=self.__kid, keys=keys)
        self.__generated = False

    def load_keys(self, kid: str = None) -> bool:
        """
        Load keys and counter from a storage

        :param kid: Unique key ID, default None
        :type str:
        :returns bool: If the key has reached its maximum payload = False
        :rtype bool:
        """
        self.__kid, result = self.__storage.load_keys(kid=kid)

        self.__public = result["data"]["keys"]["public"]
        self.__private = result["data"]["keys"]["private"]
        self.__secret_key = result["data"]["keys"]["secret"]
        self.__counter = result["data"]["counter"]
        self.__generated = True
