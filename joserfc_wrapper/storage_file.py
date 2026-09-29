"""file manipulation class"""

import os
import json
import tempfile
from contextlib import contextmanager
from typing import Iterator
from joserfc_wrapper.abstract_key_storage import (
    AbstractKeyStorage,
    KEY_CACHE_TTL,
)
from joserfc_wrapper.token_header import (
    is_valid_kid,
    jti_digest,
    require_valid_kid,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]


class StorageFile(AbstractKeyStorage):
    """interface for saving and loading a key on the file system"""

    not_found_errors = (FileNotFoundError,)

    def __init__(
        self, cert_dir: str, key_cache_ttl: int = KEY_CACHE_TTL
    ) -> None:
        """
        :param cert_dir: - path to the directory with certificates
        :param key_cache_ttl: lifetime of cached verification keys in
            seconds (default 300, 0 = no cache), see
            'AbstractKeyStorage.load_verification_key'
        :raises ValueError: invalid key_cache_ttl
        """
        self.key_cache_ttl = key_cache_ttl
        self.__cert_dir = cert_dir
        # file name for save last keys ID - default "last-key-id"
        self.last_id_name = "last-key-id"
        # lock file for writes from concurrent processes
        self.lock_name = ".lock"

    def get_last_kid(self) -> str:
        """Return last Key ID"""
        last_kid_path = os.path.join(
            self.__cert_dir, f"{self.last_id_name}.json"
        )
        with open(last_kid_path, "r", encoding="utf-8") as f:
            last_kid = json.load(f)

        return last_kid["kid"]

    def load_keys(self, kid: str = "") -> tuple[str, dict]:
        """Load keys"""
        if kid == "":
            kid = self.get_last_kid()
        return kid, self.__load_key_files(require_valid_kid(kid))

    def save_keys(self, kid: str, keys: dict) -> None:
        """Save keys and set them as the last keys"""
        require_valid_kid(kid)
        with self.__lock():
            self.__save_key_file(kid, keys)
            self.__save_last_id_file(kid)

    def replace_last_keys(self, last_kid: str, kid: str, keys: dict) -> str:
        """Atomically save new keys as the last keys (key rotation)"""
        require_valid_kid(kid)
        with self.__lock():
            current = self.get_last_kid()
            if current != last_kid:
                return current
            self.__save_key_file(kid, keys)
            self.__save_last_id_file(kid)
            return kid

    def update_metadata(self, kid: str, metadata: dict) -> None:
        """Atomically update metadata fields of a key record"""
        require_valid_kid(kid)
        with self.__lock():
            data = self.__load_key_files(kid)["data"]
            data.update(metadata)
            self.__save_key_file(kid, data)

    def list_kids(self) -> list[str]:
        """Return Key IDs of all keys in the storage"""
        return sorted(
            name[: -len(".json")]
            for name in os.listdir(self.__cert_dir)
            if name.endswith(".json") and is_valid_kid(name[: -len(".json")])
        )

    def revoke_jti(self, jti: str, expires_at: int) -> None:
        """Save a revoked token ID to revoked/<digest>.json"""
        with self.__lock():
            os.makedirs(self.__revoked_dir(), mode=0o700, exist_ok=True)
            self.__write_json(
                os.path.join(self.__revoked_dir(), f"{jti_digest(jti)}.json"),
                {"exp": expires_at},
            )

    def is_jti_revoked(self, jti: str) -> bool:
        """Return True when the token ID is revoked"""
        return os.path.exists(
            os.path.join(self.__revoked_dir(), f"{jti_digest(jti)}.json")
        )

    def prune_revoked(self, now: int) -> int:
        """Delete records of revoked tokens which expired before 'now'"""
        if not os.path.isdir(self.__revoked_dir()):
            return 0
        deleted = 0
        with self.__lock():
            for name in os.listdir(self.__revoked_dir()):
                path = os.path.join(self.__revoked_dir(), name)
                if not name.endswith(".json"):
                    continue
                with open(path, "r", encoding="utf-8") as f:
                    expires_at = json.load(f)["exp"]
                if expires_at < now:
                    os.remove(path)
                    deleted += 1
        return deleted

    def __revoked_dir(self) -> str:
        return os.path.join(self.__cert_dir, "revoked")

    def delete_keys(self, kid: str) -> None:
        """Delete keys from the storage"""
        require_valid_kid(kid)
        with self.__lock():
            os.remove(os.path.join(self.__cert_dir, f"{kid}.json"))

    @contextmanager
    def __lock(self) -> Iterator[None]:
        """
        Exclusive lock for writes, shared by processes and threads

        Without fcntl (Windows) the writes are not locked.
        """
        if fcntl is None:  # pragma: no cover - Windows
            yield
            return
        lock_path = os.path.join(self.__cert_dir, self.lock_name)
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            # closing the descriptor releases the lock
            os.close(fd)

    def __save_key_file(self, kid: str, keys: dict) -> None:
        """Save keys file, call only under the lock"""
        # must have 'data' key for HashiCorp Vault compatibility,
        # other fields of the record (metadata) are kept
        record = dict(keys)
        record["keys"] = {
            "private": keys["keys"]["private"],
            "public": keys["keys"]["public"],
            "secret": keys["keys"]["secret"],
        }
        data = {"data": record}
        keys_path = os.path.join(self.__cert_dir, f"{kid}.json")
        self.__write_json(keys_path, data)

    def __load_key_files(self, kid: str) -> dict:
        """Loads key files from the specified directory"""

        keys_path = os.path.join(self.__cert_dir, f"{kid}.json")
        with open(keys_path, "r", encoding="utf-8") as f:
            keys = json.load(f)

        return keys

    def save_last_kid(self, kid: str) -> None:
        """Save last Key ID"""
        require_valid_kid(kid)
        with self.__lock():
            self.__save_last_id_file(kid)

    def __save_last_id_file(self, kid: str) -> None:
        """Save last kid file, call only under the lock"""
        last_key = {"kid": kid}
        keys_path = os.path.join(self.__cert_dir, f"{self.last_id_name}.json")
        self.__write_json(keys_path, last_key)

    def __write_json(self, path: str, data: dict) -> None:
        """
        Atomically write JSON readable only by the owner (0600)

        The data is written to a temporary file in the same directory
        and then renamed, so a crash never leaves a partially written file.
        """
        fd, tmp_path = tempfile.mkstemp(
            dir=self.__cert_dir, prefix=".", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
        except BaseException:
            os.unlink(tmp_path)
            raise
