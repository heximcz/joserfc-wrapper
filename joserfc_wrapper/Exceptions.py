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


class KeysNotLoadedError(WrapperErrors):
    error = "Keys are not loaded."
    description = "Call 'load_keys' or 'generate_keys' first."


# JWT
class CreateTokenException(WrapperErrors):
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


class TokenSignatureError(InvalidTokenError):
    error = "Invalid token signature."


class TokenExpiredError(InvalidTokenError):
    error = "Token has expired."


class TokenNotYetValidError(InvalidTokenError):
    error = "Token is not yet valid."


class TokenClaimError(InvalidTokenError):
    error = "Invalid claim in token."
