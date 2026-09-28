import inspect
from pathlib import Path

import joserfc_wrapper
from joserfc_wrapper import Exceptions


def test_all_names_are_importable():
    for name in joserfc_wrapper.__all__:
        assert hasattr(joserfc_wrapper, name), name


def test_all_exceptions_are_exported():
    exceptions = {
        name
        for name, obj in inspect.getmembers(Exceptions, inspect.isclass)
        if issubclass(obj, Exceptions.WrapperErrors)
    }

    assert exceptions <= set(joserfc_wrapper.__all__)


def test_py_typed_marker():
    """PEP 561, type checkers use the types of the installed package"""
    assert (Path(joserfc_wrapper.__file__).parent / "py.typed").is_file()
