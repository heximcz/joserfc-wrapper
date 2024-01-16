import time
import base64
import json
import uuid
from joserfc_wrapper.exceptions import (
    ObjectTypeError,
    CreateTokenException,
    TokenKidInvalidError,
)
from joserfc_wrapper import WrapJWK
from joserfc.jwk import ECKey
from joserfc.jwt import Token, JWTClaimsRegistry

from joserfc import jwt


class WrapJWT:
    def __init__(self, wrapjwk: WrapJWK = WrapJWK()) -> None:
        """
        Handles for JWT

        :param wrapjwk: for non vault storage
        :type WrapJWK:
        """
        if not isinstance(wrapjwk, WrapJWK):
            raise ObjectTypeError
        self.__jwk = wrapjwk
        self.__kid = None

    def get_kid(self) -> str | None:
        """Return Key ID"""
        return self.__kid

    def decode(self, token: str) -> Token:
        """Decode token"""
        if self.__load_keys_decode(token):
            key = ECKey.import_key(self.__jwk.get_private_key())
            return jwt.decode(token, key)
        raise TokenKidInvalidError

    def validate(self, token: Token, valid_claims: dict) -> bool:
        """Validate claims"""
        claims_for_registry = {k: {"value": v} for k, v in valid_claims.items()}
        reg = JWTClaimsRegistry(**claims_for_registry)
        reg.validate(token.claims)

    def create(self, claims: dict, payload: int = 0) -> str:
        # TODO: Counter
        """
        Create a JWT Token with claims and signed with existing key.

        :param claims:
        :type dict:
        :param payload: 0 = unlimited. In case it is set, it checks how many times the key
          has been used for signing tokens. If the value is exceeded,
          a new key is automatically generated.
        :type int:
        :raises CreateTokenException:
        :returns: jwt token
        :rtype str:
        """
        # check required claims
        self.__check_claims(claims)

        # load last keys
        self.__load_keys()
        if payload and self.__jwk.get_counter() >= payload:
            self.__jwk.generate_keys()
            self.__jwk.save_keys()

        # create header
        headers = {"alg": "ES256", "kid": self.__jwk.get_kid()}
        # add actual iat to claims
        claims["iat"] = int(time.time())  # actual unix timestamp

        # generate token
        private = ECKey.import_key(self.__jwk.get_private_key())
        token = jwt.encode(headers, claims, private)

        # save counter
        self.__jwk.increase_counter()
        self.__jwk.save_keys()

        return token


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

    def __load_keys(self, kid: str = None) -> None:
        self.__jwk.load_keys(kid)

    def __load_keys_decode(self, token: str) -> bool | None:
        """Load right keys for a token"""
        kid = self.__decode_jwt(token)["kid"]
        if not self.__validate_kid(kid):
            return False
        self.__kid = kid
        self.__load_keys(kid)
        return True

    def __decode_jwt(self, token: str) -> str:
        """Decode token for get KID"""
        header, _, _ = token.split(".")
        decoded_header = json.loads(self.__base64_url_decode(header).decode("utf-8"))
        return decoded_header

    def __validate_kid(self, kid: str) -> bool:
        """Validate Key ID"""
        try:
            uuid_obj = uuid.UUID(kid)
            return uuid_obj.version == 4
        except ValueError:
            return False

    def __base64_url_decode(self, header: str) -> str:
        """Just b64 decode"""
        remainder = len(header) % 4
        if remainder > 0:
            header += "=" * (4 - remainder)
        return base64.urlsafe_b64decode(header)
