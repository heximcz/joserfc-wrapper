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
    TokenKeyRevokedError,
    TokenRevokedError,
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
        max_key_age: int | None = None,
        max_token_lifetime: int | None = None,
        revocation: bool = False,
        require_jti: bool = False,
    ) -> None:
        """
        :param wrapjwk: keys of the storage
        :param issuer: expected 'iss' claim, required by 'verify', added
            to the claims by 'create'
        :param audience: allowed 'aud' value(s), required by 'verify',
            added to the claims by 'create'
        :param default_exp: 'create' without 'exp' sets the expiration
            after this number of seconds
        :param max_age: a token is expired this number of seconds after
            'iat', even with a later 'exp'
        :param leeway: tolerance of clocks in seconds for 'exp', 'nbf',
            'iat' and 'max_age'
        :param max_key_age: 'create' rotates the keys after this number of
            seconds since their creation (recommended instead of 'payload')
        :param max_token_lifetime: the longest allowed lifetime of a token
            in seconds, 'create' refuses a longer 'exp', required by 'prune'
        :param revocation: 'verify' checks revoked tokens ('revoke_token'),
            the storage must support it (StorageRedis, StorageVault,
            StorageFile), one more storage read for each token
        :param require_jti: with revocation, a token without 'jti' (created
            by versions older than 0.4.0) is invalid
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
        self.max_key_age = self.__check_seconds("max_key_age", max_key_age, 1)
        self.max_token_lifetime = self.__check_seconds(
            "max_token_lifetime", max_token_lifetime, 1
        )
        if not isinstance(revocation, bool) or not isinstance(
            require_jti, bool
        ):
            raise ConfigurationError("'revocation' and 'require_jti' are bool.")
        if revocation and not wrapjwk.supports_token_revocation():
            raise ConfigurationError(
                "The storage does not support revoking tokens."
            )
        self.revocation = revocation
        self.require_jti = require_jti
        if (
            self.max_token_lifetime is not None
            and self.default_exp is not None
            and self.default_exp > self.max_token_lifetime
        ):
            raise ConfigurationError(
                "'default_exp' must not be greater than 'max_token_lifetime'."
            )

    def get_kid(self) -> str:
        """Return Key ID"""
        return self.__kid

    def decode(self, token: str) -> Token:
        """
        Decode token, verify only the signature

        It does not check any claim (expiration, issuer, audience), use
        'verify' to check a token.

        :param token: Token to decode
        :returns: object
        :raises TokenDecodeError: malformed token
        :raises TokenKidInvalidError: missing or invalid KID
        :raises KeysNotFoundError: KID is not in the storage
        :raises KeysLoadError: storage error
        :raises JoseError: invalid signature
        """
        kid = read_kid(token)
        self.__kid = kid
        self.__load_keys(kid)
        key = ECKey.import_key(self.__jwk.get_public_key())
        return jwt.decode(token, key, algorithms=["ES256"])

    def verify(self, token: str, claims: dict | None = None) -> Token:
        """
        Verify a token: signature, 'exp', 'nbf', 'iat', 'iss', 'aud',
        'max_age', a revoked key, optionally other claims and a revoked
        token ('revocation')

        A token without 'exp' is invalid.

        :param token: Token to verify
        :param claims: other claims which must be equal in the token
        :returns: valid token
        :raises ConfigurationError: 'issuer' or 'audience' is not set
        :raises InvalidTokenError: invalid token (HTTP 401), one of
            TokenDecodeError, TokenKidInvalidError, TokenKidUnknownError,
            TokenSignatureError, TokenKeyRevokedError, TokenExpiredError,
            TokenNotYetValidError, TokenClaimError, TokenRevokedError
        :raises KeysLoadError: storage error (HTTP 500)
        """
        if self.issuer is None or self.audience is None:
            raise ConfigurationError(
                "Set 'issuer' and 'audience' of WrapJWT to verify tokens."
            )
        decoded = self.__decode_signed(token)
        if self.__jwk.is_revoked():
            raise TokenKeyRevokedError(f"Key ID '{self.__kid}'.")
        self.__check_token_claims(decoded, claims or {})
        if self.revocation:
            self.__check_revoked(decoded)
        return decoded

    def validate(self, token: Token, claims: dict) -> bool:
        """
        Validate claims of a decoded token

        Deprecated, use 'verify'. The same checks as 'verify' (a token
        without 'exp' is invalid), 'issuer' and 'audience' of WrapJWT are
        checked only when they are set.

        :param token: Decoded token (call this after decode)
        :param claims: Claims which must be equal in token
        :returns: False when the token is invalid
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
        :param payload: deprecated since 0.5.0 (removed in 1.0.0), use
            'max_key_age' of WrapJWT. 0 = unlimited, otherwise the keys are
            rotated after this number of signed tokens.
        :param exp: token expires after this number of seconds, sets the
            'exp' claim, default 'default_exp' of WrapJWT, None = no
            expiration (or 'exp' in claims)
        :raises CreateTokenException:
        :returns: jwt token
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
        self.__check_lifetime(claims, exp)
        claims.setdefault("jti", uuid.uuid4().hex)
        if payload:
            warnings.warn(
                "'payload' is deprecated, use 'max_key_age' of WrapJWT",
                DeprecationWarning,
                stacklevel=2,
            )

        # load the last keys, count the token and rotate the keys by age
        # (max_key_age), revocation or payload
        self.__jwk.reserve_key(payload, self.max_key_age)

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
        :returns: jti
        :raises TokenClaimError: the token has no 'jti'
        :raises TokenDecodeError: malformed token
        :raises TokenKidInvalidError: missing or invalid KID
        :raises KeysLoadError: KID is not in the storage or storage error
        :raises JoseError: invalid signature
        """
        jti = self.decode(token).claims.get("jti")
        if not isinstance(jti, str) or not jti:
            raise TokenClaimError("Token has no 'jti'.")
        return jti

    def __check_token_claims(self, token: Token, claims: dict) -> None:
        """
        Check claims of a decoded token (shared by 'verify' and 'validate')

        :raises InvalidTokenError: invalid claims
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
        :raises CreateTokenException: invalid claims
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

    def __check_lifetime(self, claims: dict, exp: int | None) -> None:
        """
        The token must expire within max_token_lifetime (when it is set)

        :raises CreateTokenException: no exp or exp is too far
        """
        if self.max_token_lifetime is None:
            return
        if exp is None:
            if "exp" not in claims:
                raise CreateTokenException(
                    "'exp' is required when 'max_token_lifetime' is set."
                )
            claim = claims["exp"]
            if not isinstance(claim, int) or isinstance(claim, bool):
                raise CreateTokenException("Claim 'exp' must be an integer.")
            exp = claim - int(time.time())
        if exp > self.max_token_lifetime:
            raise CreateTokenException(
                f"'exp' is longer than max_token_lifetime "
                f"({self.max_token_lifetime} seconds)."
            )

    def revoke_token(self, token: str) -> None:
        """
        Revoke a single token, 'verify' with revocation then raises
        TokenRevokedError

        The signature is verified, the 'jti' is saved in the storage until
        the token expires ('exp'). An expired token is not saved.

        :param token: token to revoke
        :raises ConfigurationError: revocation is not enabled
        :raises InvalidTokenError: invalid token or signature (see
            'verify'), TokenClaimError: the token has no 'jti' or 'exp'
        :raises KeysLoadError: storage error
        :raises KeysSaveError: storage error
        """
        self.__check_revocation_enabled()
        claims = self.__decode_signed(token).claims
        jti, exp = claims.get("jti"), claims.get("exp")
        if not isinstance(jti, str) or not jti:
            raise TokenClaimError("Token has no 'jti', it cannot be revoked.")
        if not isinstance(exp, int) or isinstance(exp, bool):
            raise TokenClaimError("Token has no 'exp', it cannot be revoked.")
        if exp < int(time.time()) - self.leeway:
            return
        self.__jwk.revoke_jti(jti, exp + self.leeway)

    def revoke_jti(self, jti: str, expires_at: int) -> None:
        """
        Revoke a token by its ID, when you do not have the token (e.g. from
        a list of issued tokens of your application)

        :param jti: token ID ('jti' claim)
        :param expires_at: 'exp' of the token (unix timestamp)
        :raises ConfigurationError: revocation is not enabled
        :raises ValueError: invalid jti or expires_at
        :raises KeysSaveError: storage error
        """
        self.__check_revocation_enabled()
        if not isinstance(jti, str) or not jti:
            raise ValueError("'jti' must be a non-empty string.")
        if not isinstance(expires_at, int) or isinstance(expires_at, bool):
            raise ValueError("'expires_at' must be a unix timestamp (int).")
        self.__jwk.revoke_jti(jti, expires_at + self.leeway)

    def __decode_signed(self, token: str) -> Token:
        """
        Decode a token and verify its signature

        :raises InvalidTokenError: invalid token or signature, unknown kid
        :raises KeysLoadError: storage error
        """
        try:
            return self.decode(token)
        except KeysNotFoundError as e:
            raise TokenKidUnknownError(str(e)) from e
        except BadSignatureError as e:
            raise TokenSignatureError from e
        except JoseError as e:
            raise InvalidTokenError(str(e)) from e

    def __check_revocation_enabled(self) -> None:
        if not self.revocation:
            raise ConfigurationError(
                "Set 'revocation=True' of WrapJWT to revoke tokens."
            )

    def __check_revoked(self, token: Token) -> None:
        """
        :raises TokenRevokedError: the token is revoked
        :raises TokenClaimError: no jti and require_jti
        :raises KeysLoadError: storage error
        """
        jti = token.claims.get("jti")
        if not isinstance(jti, str) or not jti:
            if self.require_jti:
                raise TokenClaimError("Token has no 'jti' (require_jti).")
            return
        if self.__jwk.is_jti_revoked(jti):
            raise TokenRevokedError(f"jti '{jti}'.")

    def prune(self) -> list[str]:
        """
        Delete keys which cannot sign any valid token anymore and expired
        records of revoked tokens, see 'WrapJWK.prune'
        ('max_token_lifetime' and 'leeway' of WrapJWT)

        :returns: Key IDs of deleted keys
        :raises ConfigurationError: 'max_token_lifetime' is not set
        :raises KeysLoadError, KeysSaveError: storage errors
        """
        if self.max_token_lifetime is None:
            raise ConfigurationError(
                "Set 'max_token_lifetime' of WrapJWT to prune keys."
            )
        return self.__jwk.prune(self.max_token_lifetime, self.leeway)

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
