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


# JWK
class GenerateKeysError(WrapperErrors):
    error = "Error when generate new keys."


class KeysSaveError(WrapperErrors):
    error = "Unable to save keys to the storage."


class KeysLoadError(WrapperErrors):
    error = "Unable to load keys from the storage."


class KeysNotLoadedError(WrapperErrors):
    error = "Keys are not loaded."
    description = "Call 'load_keys' or 'generate_keys' first."


# JWT
class CreateTokenException(WrapperErrors):
    error = "Unexpected parameter in the claims."


class TokenKidInvalidError(WrapperErrors):
    error = "Invalid KID in token."


class TokenDecodeError(WrapperErrors):
    error = "Invalid token format."
