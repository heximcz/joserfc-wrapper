"""
Command line for joserfc_wrapper
"""

from typing import Any

from joserfc_wrapper._old_modules import old_module


def __getattr__(name: str) -> Any:
    """The deprecated module name GenJWT (since 0.8.0 gen_jwt)"""
    module = old_module(__name__, name)
    if module is None:
        raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
    return module
