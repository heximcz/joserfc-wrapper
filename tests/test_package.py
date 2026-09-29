import importlib
import inspect
from pathlib import Path

import pytest

import joserfc_wrapper
from joserfc_wrapper import exceptions


def test_all_names_are_importable():
    for name in joserfc_wrapper.__all__:
        assert hasattr(joserfc_wrapper, name), name


def test_all_exceptions_are_exported():
    classes = {
        name
        for name, obj in inspect.getmembers(exceptions, inspect.isclass)
        if issubclass(obj, exceptions.WrapperErrors)
    }

    assert classes <= set(joserfc_wrapper.__all__)


def test_py_typed_marker():
    """PEP 561, type checkers use the types of the installed package"""
    assert (Path(joserfc_wrapper.__file__).parent / "py.typed").is_file()


OLD_NAMES = [
    ("joserfc_wrapper.WrapJWT", "WrapJWT", "joserfc_wrapper.wrap_jwt"),
    ("joserfc_wrapper.WrapJWK", "WrapJWK", "joserfc_wrapper.wrap_jwk"),
    ("joserfc_wrapper.WrapJWE", "WrapJWE", "joserfc_wrapper.wrap_jwe"),
    (
        "joserfc_wrapper.StorageFile",
        "StorageFile",
        "joserfc_wrapper.storage_file",
    ),
    (
        "joserfc_wrapper.StorageVault",
        "StorageVault",
        "joserfc_wrapper.storage_vault",
    ),
    (
        "joserfc_wrapper.StorageRedis",
        "StorageRedis",
        "joserfc_wrapper.storage_redis",
    ),
    (
        "joserfc_wrapper.StorageJWKS",
        "StorageJWKS",
        "joserfc_wrapper.storage_jwks",
    ),
    (
        "joserfc_wrapper.AbstractKeyStorage",
        "AbstractKeyStorage",
        "joserfc_wrapper.abstract_key_storage",
    ),
    (
        "joserfc_wrapper.Exceptions",
        "KeysLoadError",
        "joserfc_wrapper.exceptions",
    ),
    ("joserfc_wrapper.TokenHeader", "read_kid", "joserfc_wrapper.token_header"),
    (
        "joserfc_wrapper.cli.GenJWT",
        "GenerateJWT",
        "joserfc_wrapper.cli.gen_jwt",
    ),
]


@pytest.mark.parametrize("old, name, new", OLD_NAMES)
def test_old_module_names(old, name, new):
    """Module names of versions older than 0.8.0 still work (deprecated)"""
    module = importlib.import_module(old)

    with pytest.warns(DeprecationWarning, match=f"use {new}"):
        value = getattr(module, name)
    assert value is getattr(importlib.import_module(new), name)


def test_old_module_does_not_replace_exports():
    importlib.import_module("joserfc_wrapper.WrapJWT")

    assert isinstance(joserfc_wrapper.WrapJWT, type)


def test_old_module_package_attributes():
    from joserfc_wrapper import cli  # pylint: disable=import-outside-toplevel

    assert joserfc_wrapper.Exceptions.__name__ == "joserfc_wrapper.Exceptions"
    assert cli.GenJWT.__name__ == "joserfc_wrapper.cli.GenJWT"
    with pytest.raises(AttributeError):
        getattr(joserfc_wrapper, "Missing")


def test_create_token_exception_alias():
    with pytest.warns(DeprecationWarning, match="use CreateTokenError"):
        old = joserfc_wrapper.CreateTokenException
    assert old is joserfc_wrapper.CreateTokenError
    with pytest.warns(DeprecationWarning):
        assert exceptions.CreateTokenException is exceptions.CreateTokenError
    assert "CreateTokenException" not in joserfc_wrapper.__all__
