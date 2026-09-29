import importlib
import inspect
import subprocess
import sys
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


@pytest.mark.parametrize(
    "module",
    [
        "joserfc_wrapper.WrapJWT",
        "joserfc_wrapper.Exceptions",
        "joserfc_wrapper.TokenHeader",
        "joserfc_wrapper.cli.GenJWT",
        "joserfc_wrapper.cli.upgrade_check",
    ],
)
def test_old_module_names_are_removed(module):
    """The module names of 0.x were removed in 1.0.0"""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(module)


def test_removed_names():
    for name in ("CreateTokenException", "Exceptions"):
        assert not hasattr(joserfc_wrapper, name)
    assert not hasattr(joserfc_wrapper.WrapJWT, "validate")
    assert not hasattr(joserfc_wrapper.WrapJWT, "get_kid")
    for name in ("load_keys", "generate_keys", "save_keys", "get_kid"):
        assert not hasattr(joserfc_wrapper.WrapJWK, name)
    assert not hasattr(joserfc_wrapper.AbstractKeyStorage, "increase_counter")
    assert not hasattr(joserfc_wrapper.AbstractKeyStorage, "_save_last_id")


def test_package_import_does_not_need_hvac_or_redis():
    code = (
        "import sys, joserfc_wrapper; "
        "print('hvac' in sys.modules, 'redis' in sys.modules)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )

    assert result.stdout.split() == ["False", "False"]
