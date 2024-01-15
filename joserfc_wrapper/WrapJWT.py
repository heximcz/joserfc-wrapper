import time
from joserfc_wrapper.exceptions import StorageObjectError, CreateTokenException
from joserfc_wrapper import AbstractKeyStorage, StorageVault
from joserfc.jwk import ECKey, OctKey
from joserfc import jwt


class WrapJWT:
    def __init__(self, storage: AbstractKeyStorage = StorageVault()) -> None:
        """
        Handles for JWT

        :param storage: Storage object
        :type AbstractKeyStorage:
        """
        # define storage manager
        if not isinstance(storage, AbstractKeyStorage):
            raise StorageObjectError
        self.__storage = storage

    def validate() -> bool:
        pass

    def secret() -> str:
        pass

    def unsecret() -> str:
        pass

    def create(self, claims: dict) -> str:
        """
        Create a JWT Token with claims and signed with existing key.

        :param claims:
        :type dict:
        :raises CreateTokenException: invalid claims
        :returns: jwt token
        :rtype str:
        """
        # check required claims
        self.__check_claims(claims)

        # load last keys - automatickly use last generated keys
        kid, last_keys = self.__storage.load_keys()

        # set kid
        headers = {
            "alg": "ES256",
            "kid": kid
        }
        # add dactual iat to claims
        claims["iat"] = int(time.time())  # actual unix timestamp

        keys = ECKey.import_key(last_keys["data"]["keys"]["private"])
        return jwt.encode(headers, claims, keys)


    def __check_claims(self, claims: dict) -> None | CreateTokenException:
        """
        Checks if the claim contains all required keys with valid types.

        :param claims:
        :type dict:
        :raises CreateTokenException: invalid claims
        :returns None:
        """
        required_keys = {
            "iss": str,  # Issuer expected to be a string
            "aud": str,  # Audience expected to be a string
            "uid": int,  # User ID expected to be an integer
        }

        for key, expected_type in required_keys.items():
            if key not in claims:
                raise CreateTokenException(
                    f"Missing required payload argument: '{key}'."
                )
            if not isinstance(claims[key], expected_type):
                raise CreateTokenException(
                    f"Incorrect type for payload argument '{key}': Expected {expected_type.__name__}, got {type(claims[key]).__name__}."
                )
