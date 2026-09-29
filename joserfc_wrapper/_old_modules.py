"""
Deprecated module names of versions older than 0.8.0 (removed in 1.0.0)

The modules were renamed to snake_case in 0.8.0. The old names are
registered in sys.modules as proxies, without files (Exceptions.py and
exceptions.py would collide on case-insensitive file systems). Using an
attribute of an old module raises DeprecationWarning.
"""

import importlib
import sys
import types
import warnings
from typing import Any

# old module -> new module
OLD_MODULES = {
    "joserfc_wrapper.AbstractKeyStorage": (
        "joserfc_wrapper.abstract_key_storage"
    ),
    "joserfc_wrapper.Exceptions": "joserfc_wrapper.exceptions",
    "joserfc_wrapper.StorageFile": "joserfc_wrapper.storage_file",
    "joserfc_wrapper.StorageJWKS": "joserfc_wrapper.storage_jwks",
    "joserfc_wrapper.StorageRedis": "joserfc_wrapper.storage_redis",
    "joserfc_wrapper.StorageVault": "joserfc_wrapper.storage_vault",
    "joserfc_wrapper.TokenHeader": "joserfc_wrapper.token_header",
    "joserfc_wrapper.WrapJWE": "joserfc_wrapper.wrap_jwe",
    "joserfc_wrapper.WrapJWK": "joserfc_wrapper.wrap_jwk",
    "joserfc_wrapper.WrapJWT": "joserfc_wrapper.wrap_jwt",
    "joserfc_wrapper.cli.GenJWT": "joserfc_wrapper.cli.gen_jwt",
}


class OldModule(types.ModuleType):
    """A deprecated module name, attributes come from the new module"""

    def __init__(self, name: str, new_name: str) -> None:
        super().__init__(name, f"Deprecated, use {new_name}.")
        self.new_name = new_name

    def __getattr__(self, attribute: str) -> Any:
        # the import system asks for __path__, __spec__, ... of modules
        if attribute.startswith("__"):
            raise AttributeError(attribute)
        warnings.warn(
            f"module {self.__name__} is deprecated, use {self.new_name} "
            "(or import from joserfc_wrapper)",
            DeprecationWarning,
            stacklevel=2,
        )
        return getattr(importlib.import_module(self.new_name), attribute)

    def __dir__(self) -> list[str]:
        return dir(importlib.import_module(self.new_name))


def register() -> None:
    """Register the old module names in sys.modules"""
    for old, new in OLD_MODULES.items():
        sys.modules.setdefault(old, OldModule(old, new))


def old_module(package: str, name: str) -> OldModule | None:
    """Return the old module 'package.name' (package attribute), or None"""
    module = sys.modules.get(f"{package}.{name}")
    return module if isinstance(module, OldModule) else None
