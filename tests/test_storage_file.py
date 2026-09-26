import json
import stat

import pytest

from joserfc_wrapper import AbstractKeyStorage

KEYS = {
    "keys": {
        "private": {"kty": "EC", "d": "private"},
        "public": {"kty": "EC"},
        "secret": {"kty": "oct"},
    },
    "counter": 3,
}


def test_is_key_storage(storage):
    assert isinstance(storage, AbstractKeyStorage)


def test_save_writes_vault_compatible_format(storage, tmp_path):
    storage.save_keys("kid1", KEYS)

    saved = json.loads((tmp_path / "kid1.json").read_text())
    assert saved == {"data": KEYS}
    last = json.loads((tmp_path / "last-key-id.json").read_text())
    assert last == {"kid": "kid1"}


def test_load_last_keys(storage):
    storage.save_keys("kid1", KEYS)
    storage.save_keys("kid2", {**KEYS, "counter": 7})

    assert storage.get_last_kid() == "kid2"
    kid, result = storage.load_keys()
    assert kid == "kid2"
    assert result["data"]["counter"] == 7


def test_load_keys_by_kid(storage):
    storage.save_keys("kid1", KEYS)
    storage.save_keys("kid2", {**KEYS, "counter": 7})

    kid, result = storage.load_keys("kid1")
    assert kid == "kid1"
    assert result == {"data": KEYS}


def test_load_missing_keys(storage):
    with pytest.raises(FileNotFoundError):
        storage.load_keys()


def test_saved_files_readable_only_by_owner(storage, tmp_path):
    storage.save_keys("kid1", KEYS)

    for name in ("kid1.json", "last-key-id.json"):
        mode = stat.S_IMODE((tmp_path / name).stat().st_mode)
        assert mode == 0o600, name


def test_failed_write_keeps_previous_file(storage, tmp_path):
    storage.save_keys("kid1", KEYS)
    broken = {**KEYS, "counter": object()}  # not JSON serializable

    with pytest.raises(TypeError):
        storage.save_keys("kid1", broken)

    saved = json.loads((tmp_path / "kid1.json").read_text())
    assert saved == {"data": KEYS}
    assert not list(tmp_path.glob("*.tmp"))


def test_increase_counter(storage, tmp_path):
    storage.save_keys("kid1", KEYS)
    storage.save_keys("kid2", KEYS)

    assert storage.increase_counter("kid1") == 4
    assert storage.increase_counter("kid1", limit=5) == 5
    assert storage.increase_counter("kid1", limit=5) is None
    assert storage.load_keys("kid1")[1]["data"]["counter"] == 5
    # the last Key ID is not changed
    assert storage.get_last_kid() == "kid2"


def test_replace_last_keys(storage):
    storage.save_keys("kid1", KEYS)

    assert storage.replace_last_keys("kid1", "kid2", KEYS) == "kid2"
    assert storage.get_last_kid() == "kid2"


def test_replace_last_keys_already_rotated(storage, tmp_path):
    storage.save_keys("kid1", KEYS)
    storage.save_keys("kid2", KEYS)

    assert storage.replace_last_keys("kid1", "kid3", KEYS) == "kid2"
    assert not (tmp_path / "kid3.json").exists()


def test_lock_file_readable_only_by_owner(storage, tmp_path):
    storage.save_keys("kid1", KEYS)

    assert stat.S_IMODE((tmp_path / ".lock").stat().st_mode) == 0o600
