"""joserfc_wrapper exceptions"""

from typing import Optional


class WrapperErrors(Exception):
    """Base class of joserfc_wrapper exceptions"""

    #: short-string error code
    error: str = ""
    #: long-string to describe this error
    description: str = ""

    def __init__(self, description: Optional[str] = None):
        if description is not None:
            self.description = description

        message = self.error
        if self.description:
            message = f"{self.error}: {self.description}"
        super(WrapperErrors, self).__init__(message)


class ObjectTypeError(WrapperErrors):
    error = "Not correct object type"


class ConfigurationError(WrapperErrors):
    error = "Invalid configuration."


# JWK
class GenerateKeysError(WrapperErrors):
    error = "Error when generate new keys."


class KeysSaveError(WrapperErrors):
    error = "Unable to save keys to the storage."


class KeysLoadError(WrapperErrors):
    error = "Unable to load keys from the storage."


class KeysNotFoundError(KeysLoadError):
    error = "Keys not found in the storage."


# JWT
class CreateTokenError(WrapperErrors):
    """Missing or invalid claims or 'exp'"""

    error = "Unexpected parameter in the claims."


class InvalidTokenError(WrapperErrors):
    """Base class of errors of an invalid token (HTTP 401)"""

    error = "Invalid token."


class TokenDecodeError(InvalidTokenError):
    error = "Invalid token format."


class TokenKidInvalidError(InvalidTokenError):
    error = "Invalid KID in token."


class TokenKidUnknownError(InvalidTokenError):
    error = "Unknown KID in token."


class TokenRevokedError(InvalidTokenError):
    error = "Token is revoked."


class TokenTypeError(InvalidTokenError):
    """The 'typ' header differs from 'token_type' of WrapJWT"""

    error = "Invalid token type."


class TokenKeyRevokedError(InvalidTokenError):
    error = "The key of the token is revoked."


class TokenSignatureError(InvalidTokenError):
    error = "Invalid token signature."


class TokenExpiredError(InvalidTokenError):
    error = "Token has expired."


class TokenNotYetValidError(InvalidTokenError):
    error = "Token is not yet valid."


class TokenClaimError(InvalidTokenError):
    error = "Invalid claim in token."
