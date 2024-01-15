import pytest
from joserfc_wrapper import AbstractKeyStorage
from joserfc_wrapper import jwk
from unittest.mock import Mock

class MockStorage(AbstractKeyStorage):
    def get_last_kid(self):
        pass

    def load_keys(self, kid):
        return {}, {}

    def save_keys(self, kid, private_key, public_key):
        pass

@pytest.fixture
def valid_storage():
    return MockStorage()

def test_jwk_initialization_with_valid_storage(valid_storage):
    jwk_instance = jwk(valid_storage)
    assert jwk_instance is not None

def test_jwk_get_key_id_with_no_key(valid_storage):
    jwk_instance = jwk(valid_storage)
    assert jwk_instance.get_kid() is None

def test_jwk_get_public_key(valid_storage):
    jwk_instance = jwk(valid_storage)
    assert jwk_instance.get_public_key() is None

def test_jwk_get_private_key(valid_storage):
    jwk_instance = jwk(valid_storage)
    assert jwk_instance.get_private_key() is None

def test_jwk_generate_keys(valid_storage):
    jwk_instance = jwk(valid_storage)
    assert jwk_instance.get_private_key() is None

