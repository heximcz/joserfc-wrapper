import time
from joserfc_wrapper.exceptions import ObjectTypeError, CreateTokenException
from joserfc_wrapper import WrapJWK
from joserfc.jwk import ECKey
from joserfc import jwt


class WrapJWT:
    def __init__(self, wrapjwk: WrapJWK = WrapJWK()) -> None:
        """
        Handles for JWT

        :param wrapjwk: by default new instance
        :type WrapJWK:
        """
        # define storage manager
        if not isinstance(wrapjwk, WrapJWK):
            raise ObjectTypeError
        
        self.__jwk = wrapjwk

        # load last keys if no exist in jwk
        if not self.__jwk.get_private_key():
            self.__jwk.load_keys()

    def validate() -> bool:
        pass

    def create(self, claims: dict) -> str:
        # TODO: Counter
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

        # create header
        headers = {
            "alg": "ES256",
            "kid": self.__jwk.get_kid()
        }
        # add actual iat to claims
        claims["iat"] = int(time.time())  # actual unix timestamp

        private = ECKey.import_key(self.__jwk.get_private_key())
        return jwt.encode(headers, claims, private)

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
