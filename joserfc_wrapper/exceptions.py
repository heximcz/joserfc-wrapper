"""joserfc_wrapper exceptions"""

import warnings
from typing import TYPE_CHECKING, Optional


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
class CreateTokenError(WrapperErrors):
    """Missing or invalid claims or 'exp' (renamed in 0.8.0)"""

    error = "Unexpected parameter in the claims."


# deprecated names: old name -> new name
DEPRECATED = {"CreateTokenException": "CreateTokenError"}

if TYPE_CHECKING:
    #: deprecated since 0.8.0 (removed in 1.0.0), use CreateTokenError
    CreateTokenException = CreateTokenError


def deprecated_name(module: str, name: str) -> type:
    """
    Return the class of a deprecated name with DeprecationWarning (module
    __getattr__ of this module and of the package)

    :raises AttributeError: unknown name
    """
    new = DEPRECATED.get(name)
    if new is None:
        raise AttributeError(f"module '{module}' has no attribute '{name}'")
    warnings.warn(
        f"{name} is deprecated, use {new}", DeprecationWarning, stacklevel=3
    )
    return globals()[new]


def __getattr__(name: str) -> type:
    return deprecated_name(__name__, name)


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
    """The 'typ' header differs from 'token_type' of WrapJWT (since 0.9.0)"""

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
