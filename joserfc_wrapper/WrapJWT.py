"""joserfc jwt wrapper"""

import time
import uuid
import warnings
from joserfc_wrapper.Exceptions import (
    ObjectTypeError,
    ConfigurationError,
    CreateTokenException,
    InvalidTokenError,
    KeysNotFoundError,
    TokenClaimError,
    TokenExpiredError,
    TokenKidUnknownError,
    TokenNotYetValidError,
    TokenSignatureError,
)
from joserfc_wrapper.TokenHeader import read_kid
from joserfc_wrapper.WrapJWK import WrapJWK

from joserfc import jwt
from joserfc.errors import (
    BadSignatureError,
    ClaimError,
    ExpiredTokenError,
    JoseError,
)
from joserfc.jwk import ECKey
from joserfc.jwt import Token, JWTClaimsRegistry, ClaimsOption


class WrapJWT:
    """Handles for JWT"""

    def __init__(
        self,
        wrapjwk: WrapJWK,
        issuer: str | None = None,
        audience: str | list[str] | None = None,
        default_exp: int | None = None,
        max_age: int | None = None,
        leeway: int = 0,
    ) -> None:
        """
        :param wrapjwk: keys of the storage
        :type WrapJWK:
        :param issuer: expected 'iss' claim, required by 'verify', added
            to the claims by 'create'
        :type str | None:
        :param audience: allowed 'aud' value(s), required by 'verify',
            added to the claims by 'create'
        :type str | list[str] | None:
        :param default_exp: 'create' without 'exp' sets the expiration
            after this number of seconds
        :type int | None:
        :param max_age: a token is expired this number of seconds after
            'iat', even with a later 'exp'
        :type int | None:
        :param leeway: tolerance of clocks in seconds for 'exp', 'nbf',
            'iat' and 'max_age'
        :type int:
        :raises ObjectTypeError: wrapjwk is not WrapJWK
        :raises ConfigurationError: invalid parameters
        """
        if not isinstance(wrapjwk, WrapJWK):
            raise ObjectTypeError
        self.__jwk: WrapJWK = wrapjwk
        self.__kid: str = ""

        if issuer is not None and (not isinstance(issuer, str) or not issuer):
            raise ConfigurationError("'issuer' must be a non-empty string.")
        self.issuer = issuer
        self.audience = self.__check_audience(audience)
        self.default_exp = self.__check_seconds("default_exp", default_exp, 1)
        self.max_age = self.__check_seconds("max_age", max_age, 1)
        self.leeway = self.__check_seconds("leeway", leeway, 0) or 0

    def get_kid(self) -> str:
        """Return Key ID"""
        return self.__kid

    def decode(self, token: str) -> Token:
        """
        Decode token, verify only the signature

        It does not check any claim (expiration, issuer, audience), use
        'verify' to check a token.

        :param token: Token to decode
        :type str:
        :returns: object
        :rtype Token:
        :raise TokenDecodeError: malformed token
        :raise TokenKidInvalidError: missing or invalid KID
        :raise KeysNotFoundError: KID is not in the storage
        :raise KeysLoadError: storage error
        :raise JoseError: invalid signature
        """
        kid = read_kid(token)
        self.__kid = kid
        self.__load_keys(kid)
        key = ECKey.import_key(self.__jwk.get_public_key())
        return jwt.decode(token, key, algorithms=["ES256"])

    def verify(self, token: str, claims: dict | None = None) -> Token:
        """
        Verify a token: signature, 'exp', 'nbf', 'iat', 'iss', 'aud',
        'max_age' and optionally other claims

        A token without 'exp' is invalid.

        :param token: Token to verify
        :type str:
        :param claims: other claims which must be equal in the token
        :type dict | None:
        :returns: valid token
        :rtype Token:
        :raise ConfigurationError: 'issuer' or 'audience' is not set
        :raise InvalidTokenError: invalid token (HTTP 401), one of
            TokenDecodeError, TokenKidInvalidError, TokenKidUnknownError,
            TokenSignatureError, TokenExpiredError, TokenNotYetValidError,
            TokenClaimError
        :raise KeysLoadError: storage error (HTTP 500)
        """
        if self.issuer is None or self.audience is None:
            raise ConfigurationError(
                "Set 'issuer' and 'audience' of WrapJWT to verify tokens."
            )
        try:
            decoded = self.decode(token)
        except KeysNotFoundError as e:
            raise TokenKidUnknownError(str(e)) from e
        except BadSignatureError as e:
            raise TokenSignatureError from e
        except JoseError as e:
            raise InvalidTokenError(str(e)) from e
        self.__check_token_claims(decoded, claims or {})
        return decoded

    def validate(self, token: Token, claims: dict) -> bool:
        """
        Validate claims of a decoded token

        Deprecated, use 'verify'. The same checks as 'verify' (a token
        without 'exp' is invalid), 'issuer' and 'audience' of WrapJWT are
        checked only when they are set.

        :param token: Decoded token (call this after decode)
        :type Token:
        :param claims: Claims which must be equal in token
        :type dict:
        :returns: False when the token is invalid
        :rtype bool:
        """
        warnings.warn(
            "WrapJWT.validate is deprecated, use WrapJWT.verify",
            DeprecationWarning,
            stacklevel=2,
        )
        try:
            self.__check_token_claims(token, claims)
            return True
        except InvalidTokenError:
            return False

    def create(
        self, claims: dict, payload: int = 0, exp: int | None = None
    ) -> str:
        """
        Create a JWT Token with claims and signed with existing key.

        'iss' and 'aud' are added from WrapJWT when they are not in the
        claims, 'jti' (unique token ID) is always added when it is not in
        the claims.

        :param claims:
        :type dict:
        :param payload: 0 = unlimited. In case it is set, it checks how many
            times the key has been used for signing tokens. If the value
            is exceeded, a new key is automatically generated.
        :type int:
        :param exp: token expires after this number of seconds, sets the
            'exp' claim, default 'default_exp' of WrapJWT, None = no
            expiration (or 'exp' in claims)
        :type int | None:
        :raises CreateTokenException:
        :returns: jwt token
        :rtype str:
        """
        # do not modify the caller's claims
        claims = dict(claims)
        self.__add_configured_claims(claims)
        # check required claims
        self.__check_claims(claims)
        self.__check_exp(claims, exp)
        self.__check_jti(claims)
        if exp is None and "exp" not in claims:
            exp = self.default_exp
        claims.setdefault("jti", uuid.uuid4().hex)

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

    def get_jti(self, token: str) -> str:
        """
        Return the unique token ID ('jti') after verifying the signature

        :param token: token
        :type str:
        :returns: jti
        :rtype str:
        :raise TokenClaimError: the token has no 'jti'
        :raise TokenDecodeError, TokenKidInvalidError, KeysLoadError,
            JoseError: see 'decode'
        """
        jti = self.decode(token).claims.get("jti")
        if not isinstance(jti, str) or not jti:
            raise TokenClaimError("Token has no 'jti'.")
        return jti

    def __check_token_claims(self, token: Token, claims: dict) -> None:
        """
        Check claims of a decoded token (shared by 'verify' and 'validate')

        :raise InvalidTokenError: invalid claims
        """
        options: dict[str, ClaimsOption] = {
            "exp": {"essential": True},
        }
        if self.issuer is not None:
            options["iss"] = {"essential": True, "value": self.issuer}
        if self.audience is not None:
            options["aud"] = {"essential": True, "values": self.audience}
        for key, value in claims.items():
            options[key] = {
                "essential": True,
                "allow_blank": False,
                "value": value,
            }

        try:
            JWTClaimsRegistry(None, self.leeway, **options).validate(
                token.claims
            )
        except ExpiredTokenError as e:
            raise TokenExpiredError from e
        except ClaimError as e:
            if e.claim == "nbf":
                raise TokenNotYetValidError from e
            raise TokenClaimError(e.description) from e
        except JoseError as e:
            raise TokenClaimError(str(e)) from e

        if self.max_age is not None:
            iat = token.claims.get("iat")
            if not isinstance(iat, int) or isinstance(iat, bool):
                raise TokenClaimError("Missing claim 'iat' (max_age is set).")
            if iat + self.max_age < int(time.time()) - self.leeway:
                raise TokenExpiredError("Token is older than max_age.")

    def __add_configured_claims(self, claims: dict) -> None:
        """
        Add 'iss' and 'aud' from WrapJWT, they must match when present

        :raises CreateTokenException: 'iss' or 'aud' differs
        """
        if self.issuer is not None:
            if "iss" not in claims:
                claims["iss"] = self.issuer
            elif claims["iss"] != self.issuer:
                raise CreateTokenException(
                    f"Claim 'iss' differs from the issuer '{self.issuer}'."
                )
        if self.audience is not None:
            if "aud" not in claims:
                claims["aud"] = (
                    self.audience[0]
                    if len(self.audience) == 1
                    else list(self.audience)
                )
            else:
                aud = claims["aud"]
                values = aud if isinstance(aud, list) else [aud]
                if not values or any(v not in self.audience for v in values):
                    raise CreateTokenException(
                        f"Claim 'aud' is not in the audience {self.audience}."
                    )

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
            "aud": (str, list),  # Audience, a string or a list of strings
            "uid": int,  # User ID expected to be an integer
        }

        for key, expected_type in required_keys.items():
            if key not in claims:
                raise CreateTokenException(
                    f"Missing required claims argument: '{key}'."
                )
            value = claims[key]
            # bool is a subclass of int
            if not isinstance(value, expected_type) or isinstance(value, bool):
                raise CreateTokenException(
                    f"Incorrect type for claims argument '{key}': "
                    f"got '{type(value).__name__}'."
                )
        aud = claims["aud"]
        if isinstance(aud, list) and (
            not aud or not all(isinstance(v, str) and v for v in aud)
        ):
            raise CreateTokenException(
                "Claim 'aud' must be a string or a list of non-empty strings."
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

    @staticmethod
    def __check_jti(claims: dict) -> None:
        """
        A custom 'jti' must be a non-empty string

        :raises CreateTokenException: invalid jti
        """
        if "jti" in claims and (
            not isinstance(claims["jti"], str) or not claims["jti"]
        ):
            raise CreateTokenException(
                "Claim 'jti' must be a non-empty string."
            )

    @staticmethod
    def __check_audience(audience: str | list[str] | None) -> list[str] | None:
        """
        Audience as a list of non-empty strings

        :raises ConfigurationError: invalid audience
        """
        if audience is None:
            return None
        values = [audience] if isinstance(audience, str) else audience
        if (
            not isinstance(values, list)
            or not values
            or not all(isinstance(v, str) and v for v in values)
        ):
            raise ConfigurationError(
                "'audience' must be a non-empty string or a list of them."
            )
        return list(values)

    @staticmethod
    def __check_seconds(
        name: str, value: int | None, minimum: int
    ) -> int | None:
        """
        Number of seconds, None = not set

        :raises ConfigurationError: not an integer or lower than minimum
        """
        if value is None:
            return None
        # bool is a subclass of int
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < minimum
        ):
            raise ConfigurationError(
                f"'{name}' must be an integer {minimum} or greater (seconds)."
            )
        return value

    def __load_keys(self, kid: str = "") -> None:
        self.__jwk.load_keys(kid)
