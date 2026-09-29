"""joserfc_wrapper"""

from typing import TYPE_CHECKING, Any

from ._old_modules import old_module, register
from .exceptions import deprecated_name
from .exceptions import (
    WrapperErrors,
    ObjectTypeError,
    GenerateKeysError,
    KeysSaveError,
    KeysLoadError,
    KeysNotLoadedError,
    CreateTokenError,
    ConfigurationError,
    KeysNotFoundError,
    InvalidTokenError,
    TokenDecodeError,
    TokenKidInvalidError,
    TokenKidUnknownError,
    TokenKeyRevokedError,
    TokenRevokedError,
    TokenSignatureError,
    TokenExpiredError,
    TokenNotYetValidError,
    TokenClaimError,
)
from .abstract_key_storage import AbstractKeyStorage
from .storage_vault import StorageVault
from .storage_file import StorageFile
from .storage_redis import StorageRedis
from .storage_jwks import StorageJWKS
from .wrap_jwk import WrapJWK
from .wrap_jwt import WrapJWT
from .wrap_jwe import WrapJWE

# public API, explicitly exported for type checkers (py.typed)
__all__ = [
    "WrapperErrors",
    "ObjectTypeError",
    "GenerateKeysError",
    "KeysSaveError",
    "KeysLoadError",
    "KeysNotLoadedError",
    "CreateTokenError",
    "ConfigurationError",
    "KeysNotFoundError",
    "InvalidTokenError",
    "TokenDecodeError",
    "TokenKidInvalidError",
    "TokenKidUnknownError",
    "TokenKeyRevokedError",
    "TokenRevokedError",
    "TokenSignatureError",
    "TokenExpiredError",
    "TokenNotYetValidError",
    "TokenClaimError",
    "AbstractKeyStorage",
    "StorageVault",
    "StorageFile",
    "StorageRedis",
    "StorageJWKS",
    "WrapJWK",
    "WrapJWT",
    "WrapJWE",
]


if TYPE_CHECKING:
    #: deprecated since 0.8.0 (removed in 1.0.0), use CreateTokenError
    CreateTokenException = CreateTokenError


# module names of versions older than 0.8.0 (deprecated)
register()


def __getattr__(name: str) -> Any:
    """Deprecated names with DeprecationWarning"""
    module = old_module(__name__, name)
    if module is not None:
        return module
    return deprecated_name(__name__, name)
