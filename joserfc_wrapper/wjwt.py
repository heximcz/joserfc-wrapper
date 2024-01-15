import time
from joserfc_wrapper.exceptions import StorageObjectError, CreateTokenException
from joserfc_wrapper import AbstractKeyStorage
from joserfc_wrapper import svault
from joserfc.jwk import ECKey, OctKey
from joserfc import jwt


class wjwt:
    def __init__(self, storage: AbstractKeyStorage = svault()) -> None:
        """
        Handles for JWT

        :param storage: Storage object
        :type AbstractKeyStorage:
        """
        # define storage manager
        if not isinstance(storage, AbstractKeyStorage):
            raise StorageObjectError
        self.__storage = storage

    # def get_token(self) -> str | None:
    #     """
    #     Returns the generated token.

    #     :returns: The JWT token, or None if not yet created.
    #     :rtype str | None:
    #     """
    #     return self.__token

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

        # load last keys
        kid, last_keys = self.__storage.load_keys()
        # print(last_keys["data"]["keys"]["private"])
        # exit(0)

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

        Params:
            claims: The payload to check.

        Raises:
            CreateTokenException: If required payload arguments are missing or invalid.
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
