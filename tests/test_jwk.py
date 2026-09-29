import uuid

import pytest

from joserfc_wrapper import (
    AbstractKeyStorage,
    KeysLoadError,
    KeysNotLoadedError,
    KeysSaveError,
    ObjectTypeError,
    WrapJWK,
    WrapJWT,
)


class LegacyStorage(AbstractKeyStorage):
    """Custom storage implementing only the methods of version 0.2"""

    def __init__(self) -> None:
        self.data: dict = {}

    def get_last_kid(self) -> str:
        return self.data["last-key-id"]["kid"]

    def load_keys(self, kid: str = "") -> tuple[str, dict]:
        kid = kid or self.get_last_kid()
        return kid, {"data": self.data[kid]}

    def save_keys(self, kid: str, keys: dict) -> None:
        self.data[kid] = keys
        self._save_last_id(kid)

    def _save_last_id(self, kid: str) -> None:
        self.data["last-key-id"] = {"kid": kid}


def test_requires_key_storage():
    with pytest.raises(ObjectTypeError):
        WrapJWK(object())  # type: ignore[arg-type]


def test_generate_keys(storage):
    jwk = WrapJWK(storage)
    jwk.generate_keys()

    assert uuid.UUID(jwk.get_kid()).version == 4
    assert jwk.get_kid() == jwk.get_kid().lower()
    assert jwk.get_private_key()["crv"] == "P-256"
    assert "d" in jwk.get_private_key()
    assert "d" not in jwk.get_public_key()
    assert jwk.get_secret_key()["kty"] == "oct"
    assert jwk.get_counter() == 0


def test_generate_new_kid(storage):
    jwk = WrapJWK(storage)
    jwk.generate_keys()
    first = jwk.get_kid()
    jwk.generate_keys()

    assert jwk.get_kid() != first


def test_save_and_load(jwk, storage):
    jwk.increase_counter()
    jwk.save_keys()

    loaded = WrapJWK(storage)
    loaded.load_keys()

    assert loaded.get_kid() == jwk.get_kid()
    assert loaded.get_private_key() == jwk.get_private_key()
    assert loaded.get_public_key() == jwk.get_public_key()
    assert loaded.get_secret_key() == jwk.get_secret_key()
    assert loaded.get_counter() == 1


def test_load_by_kid(jwk, storage):
    first = jwk.get_kid()
    jwk.generate_keys()
    jwk.save_keys()

    loaded = WrapJWK(storage)
    loaded.load_keys(first)

    assert loaded.get_kid() == first


def test_reserve_key(jwk, storage):
    jwk.reserve_key()
    jwk.reserve_key()

    assert jwk.get_counter() == 2
    assert storage.load_keys()[1]["data"]["counter"] == 2


def test_reserve_key_rotates(jwk, storage):
    first = jwk.get_kid()
    for _ in range(3):
        jwk.reserve_key(payload=2)

    assert jwk.get_kid() != first
    assert storage.get_last_kid() == jwk.get_kid()
    assert storage.load_keys(first)[1]["data"]["counter"] == 2
    assert jwk.get_counter() == 1


def test_reserve_key_uses_keys_rotated_by_other_process(jwk, storage):
    first = jwk.get_kid()
    for _ in range(2):
        jwk.reserve_key(payload=2)
    other = WrapJWK(storage)
    other.reserve_key(payload=2)  # rotates
    # jwk still has the first keys loaded, reserve_key loads the last keys
    jwk.reserve_key(payload=2)

    assert jwk.get_kid() == other.get_kid() != first
    assert jwk.get_counter() == 2


def test_reserve_key_gives_up(jwk, storage, monkeypatch):
    monkeypatch.setattr(type(storage), "increase_counter", lambda *a, **k: None)

    with pytest.raises(KeysSaveError):
        jwk.reserve_key(payload=1)


@pytest.mark.filterwarnings("ignore:.payload. is deprecated:DeprecationWarning")
def test_legacy_storage(claims):
    storage = LegacyStorage()
    jwk = WrapJWK(storage)
    jwk.generate_keys()
    jwk.save_keys()
    first = jwk.get_kid()
    jwt = WrapJWT(jwk)

    tokens = [jwt.create(dict(claims), payload=2) for _ in range(3)]

    assert storage.data[first]["counter"] == 2
    assert storage.get_last_kid() == jwk.get_kid() != first
    assert jwt.decode(tokens[0]).claims["uid"] == claims["uid"]


def test_legacy_storage_counter_keeps_last_kid():
    storage = LegacyStorage()
    jwk = WrapJWK(storage)
    jwk.generate_keys()
    jwk.save_keys()
    first = jwk.get_kid()
    jwk.generate_keys()
    jwk.save_keys()

    assert storage.increase_counter(first) == 1
    assert storage.get_last_kid() == jwk.get_kid()


@pytest.mark.parametrize(
    "method",
    [
        "get_kid",
        "get_public_key",
        "get_private_key",
        "get_secret_key",
        "get_counter",
        "increase_counter",
        "save_keys",
    ],
)
def test_keys_not_loaded(storage, method):
    with pytest.raises(KeysNotLoadedError):
        getattr(WrapJWK(storage), method)()


def test_load_missing_keys(storage):
    with pytest.raises(KeysLoadError) as exc:
        WrapJWK(storage).load_keys()

    assert isinstance(exc.value.__cause__, FileNotFoundError)


def test_load_unknown_kid(jwk, storage):
    with pytest.raises(KeysLoadError):
        WrapJWK(storage).load_keys(uuid.uuid4().hex)


def test_failed_load_keeps_loaded_keys(jwk):
    kid = jwk.get_kid()
    with pytest.raises(KeysLoadError):
        jwk.load_keys(uuid.uuid4().hex)

    assert jwk.get_kid() == kid


def test_save_error(jwk, storage, monkeypatch):
    def broken(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(type(storage), "save_keys", broken)

    with pytest.raises(KeysSaveError, match="OSError: disk full") as exc:
        jwk.save_keys()
    assert isinstance(exc.value.__cause__, OSError)


def test_reserve_key_storage_error(jwk, storage, monkeypatch):
    def broken(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(type(storage), "increase_counter", broken)

    with pytest.raises(KeysSaveError):
        jwk.reserve_key()


def test_incomplete_keys_in_storage(jwk, storage, tmp_path):
    kid = jwk.get_kid()
    broken = uuid.uuid4().hex
    (tmp_path / f"{broken}.json").write_text('{"data": {"counter": 0}}')

    with pytest.raises(KeysLoadError, match="KeyError"):
        jwk.load_keys(broken)
    assert jwk.get_kid() == kid
