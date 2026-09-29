import uuid
import json
import stat

import pytest

from joserfc_wrapper import AbstractKeyStorage

KID1, KID2, KID3 = (uuid.uuid4().hex for _ in range(3))

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
    storage.save_keys(KID1, KEYS)

    saved = json.loads((tmp_path / f"{KID1}.json").read_text())
    assert saved == {"data": KEYS}
    last = json.loads((tmp_path / "last-key-id.json").read_text())
    assert last == {"kid": KID1}


def test_load_last_keys(storage):
    storage.save_keys(KID1, KEYS)
    storage.save_keys(KID2, {**KEYS, "counter": 7})

    assert storage.get_last_kid() == KID2
    kid, result = storage.load_keys()
    assert kid == KID2
    assert result["data"]["counter"] == 7


def test_load_keys_by_kid(storage):
    storage.save_keys(KID1, KEYS)
    storage.save_keys(KID2, {**KEYS, "counter": 7})

    kid, result = storage.load_keys(KID1)
    assert kid == KID1
    assert result == {"data": KEYS}


def test_load_missing_keys(storage):
    with pytest.raises(FileNotFoundError):
        storage.load_keys()


def test_saved_files_readable_only_by_owner(storage, tmp_path):
    storage.save_keys(KID1, KEYS)

    for name in (f"{KID1}.json", "last-key-id.json"):
        mode = stat.S_IMODE((tmp_path / name).stat().st_mode)
        assert mode == 0o600, name


def test_failed_write_keeps_previous_file(storage, tmp_path):
    storage.save_keys(KID1, KEYS)
    broken = {**KEYS, "counter": object()}  # not JSON serializable

    with pytest.raises(TypeError):
        storage.save_keys(KID1, broken)

    saved = json.loads((tmp_path / f"{KID1}.json").read_text())
    assert saved == {"data": KEYS}
    assert not list(tmp_path.glob("*.tmp"))


def test_replace_last_keys(storage):
    storage.save_keys(KID1, KEYS)

    assert storage.replace_last_keys(KID1, KID2, KEYS) == KID2
    assert storage.get_last_kid() == KID2


def test_replace_last_keys_already_rotated(storage, tmp_path):
    storage.save_keys(KID1, KEYS)
    storage.save_keys(KID2, KEYS)

    assert storage.replace_last_keys(KID1, KID3, KEYS) == KID2
    assert not (tmp_path / f"{KID3}.json").exists()


def test_lock_file_readable_only_by_owner(storage, tmp_path):
    storage.save_keys(KID1, KEYS)

    assert stat.S_IMODE((tmp_path / ".lock").stat().st_mode) == 0o600
