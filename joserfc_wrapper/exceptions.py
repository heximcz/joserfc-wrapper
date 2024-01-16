from typing import Optional


class WrapperErrors(Exception):
    #: short-string error code
    error: str = ""
    #: long-string to describe this error
    description: str = ""

    def __init__(self, description: Optional[str] = None):
        if description is not None:
            self.description = description

        message = "{}: {}".format(self.error, self.description)
        super(WrapperErrors, self).__init__(message)


class ObjectTypeError(WrapperErrors):
    error = "Not correct object type"


# JWK
class GenerateKeysError(WrapperErrors):
    error = "Error when generate new keys."
    description = "Check path."


class KeysSaveError(WrapperErrors):
    error = "Unable to save files. Check the path is correct."


class KeysLoadError(WrapperErrors):
    error = "Unable to load files. Check the path is correct."


# JWT
class CreateTokenException(WrapperErrors):
    error = "Unexpected parameter in the claims."


class TokenKidInvalidError(WrapperErrors):
    error = "Invalid KID in token."
