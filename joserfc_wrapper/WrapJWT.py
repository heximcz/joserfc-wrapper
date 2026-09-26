"""joserfc jwt wrapper"""

import time
from joserfc_wrapper.Exceptions import (
    ObjectTypeError,
    CreateTokenException,
)
from joserfc_wrapper.TokenHeader import read_kid
from joserfc_wrapper.WrapJWK import WrapJWK

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import ECKey
from joserfc.jwt import Token, JWTClaimsRegistry, ClaimsOption


class WrapJWT:
    """Handles for JWT"""

    def __init__(self, wrapjwk: WrapJWK) -> None:
        """
        :param wrapjwk: for non vault storage
        :type WrapJWK:
        """
        if not isinstance(wrapjwk, WrapJWK):
            raise ObjectTypeError
        self.__jwk: WrapJWK = wrapjwk
        self.__kid: str = ""

    def get_kid(self) -> str:
        """Return Key ID"""
        return self.__kid

    def decode(self, token: str) -> Token:
        """
        Decode token

        :param token: Token to decode
        :type str:
        :returns: object
        :rtype Token:
        :raise TokenDecodeError: malformed token
        :raise TokenKidInvalidError: missing or invalid KID
        :raise JoseError: invalid signature
        """
        kid = read_kid(token)
        self.__kid = kid
        self.__load_keys(kid)
        key = ECKey.import_key(self.__jwk.get_public_key())
        return jwt.decode(token, key, algorithms=["ES256"])

    def validate(self, token: Token, claims: dict) -> bool:
        """
        Validate claims

        :param token: Validated token (call this after decode)
        :type str:
        :param claims: Claims keys to must be equal in token
        :type dict:
        :returns: False when a claim is missing or invalid, or the token
            is expired or not yet valid ('exp', 'nbf')
        :rtype bool:
        """
        try:
            claims_for_registry: dict[str, ClaimsOption] = {
                k: {"essential": True, "allow_blank": False, "value": v}
                for k, v in claims.items()
            }
            reg = JWTClaimsRegistry(None, 0, **claims_for_registry)
            reg.validate(token.claims)
            return True
        except JoseError:
            return False

    def create(
        self, claims: dict, payload: int = 0, exp: int | None = None
    ) -> str:
        """
        Create a JWT Token with claims and signed with existing key.

        A token without 'exp' is valid as long as its key exists
        in the storage.

        :param claims:
        :type dict:
        :param payload: 0 = unlimited. In case it is set, it checks how many
            times the key has been used for signing tokens. If the value
            is exceeded, a new key is automatically generated.
        :type int:
        :param exp: token expires after this number of seconds, sets the
            'exp' claim, None = no expiration (or 'exp' in claims)
        :type int | None:
        :raises CreateTokenException:
        :returns: jwt token
        :rtype str:
        """
        # check required claims
        self.__check_claims(claims)
        self.__check_exp(claims, exp)
        # do not modify the caller's claims
        claims = dict(claims)

        # load the last keys, count the token and rotate keys by payload
        self.__jwk.reserve_key(payload)

        # create header
        headers = {"alg": "ES256", "kid": self.__jwk.get_kid()}
        # add actual iat to claims
        claims["iat"] = int(time.time())  # actual unix timestamp
        if exp is not None:
            claims["exp"] = claims["iat"] + exp

        # generate token
        private = ECKey.import_key(self.__jwk.get_private_key())
        token = jwt.encode(headers, claims, private)

        return token

    def __check_claims(self, claims: dict) -> None:
        """
        Checks if the claims contains all required keys with valid types.

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
                    f"Missing required claims argument: '{key}'."
                )
            # bool is a subclass of int
            if not isinstance(claims[key], expected_type) or isinstance(
                claims[key], bool
            ):
                raise CreateTokenException(
                    f"Incorrect type for claims argument '{key}': "
                    f"Expected '{expected_type.__name__}', "
                    f"got '{type(claims[key]).__name__}'."
                )

    def __check_exp(self, claims: dict, exp: int | None) -> None:
        """
        Checks the expiration parameter

        :raises CreateTokenException: invalid exp or 'exp' also in claims
        """
        if exp is None:
            return
        # bool is a subclass of int
        if not isinstance(exp, int) or isinstance(exp, bool) or exp <= 0:
            raise CreateTokenException(
                "Parameter 'exp' must be a positive integer (seconds)."
            )
        if "exp" in claims:
            raise CreateTokenException(
                "Set the expiration by the 'exp' parameter or in claims, "
                "not both."
            )

    def __load_keys(self, kid: str = "") -> None:
        self.__jwk.load_keys(kid)
