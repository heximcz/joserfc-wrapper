"""vault manipulation class"""

import warnings
from typing import Any

from joserfc_wrapper.abstract_key_storage import (
    AbstractKeyStorage,
    KEY_CACHE_TTL,
)
from joserfc_wrapper.exceptions import KeysSaveError
from joserfc_wrapper.token_header import is_valid_kid, jti_digest


class StorageVault(AbstractKeyStorage):
    """interface for saving and loading a key on the HashiCorp Vault system"""

    # attempts to write with check-and-set before giving up
    cas_attempts = 100

    def __init__(
        self,
        url: str = "",
        token: str = "",
        mount: str = "",
        kv_version: int = 2,
        key_cache_ttl: int = KEY_CACHE_TTL,
    ) -> None:
        """
        Handles for HashiCorp Vault Storage

        :param url: - Vault URL
        :param token: - Token
        :param mount: - Vault mount point
        :param kv_version: - version of the KV secrets engine, 2 (default)
            uses check-and-set and is safe for concurrent processes,
            1 is for keys saved by older versions, is not atomic and is
            deprecated (removed in 1.0.0)
        :param key_cache_ttl: lifetime of cached verification keys in
            seconds (default 300, 0 = no cache), see
            'AbstractKeyStorage.load_verification_key'
        :raises ValueError: unsupported kv_version, invalid key_cache_ttl
        :raises ImportError: hvac is not installed (an optional dependency
            since 1.0.0: pip install joserfc-wrapper[vault])
        """
        self.key_cache_ttl = key_cache_ttl
        hvac = import_hvac()
        self.__invalid_path = hvac.exceptions.InvalidPath
        self.__invalid_request = hvac.exceptions.InvalidRequest
        self.not_found_errors = (self.__invalid_path,)
        if kv_version not in (1, 2):
            raise ValueError("kv_version must be 1 or 2")
        if kv_version == 1:
            warnings.warn(
                "KV v1 (kv_version=1) is deprecated and will be removed in "
                "1.0.0, move the keys to a KV v2 mount",
                DeprecationWarning,
                stacklevel=2,
            )
        self.url = url
        self.mount = mount
        self.kv_version = kv_version
        self.__client = hvac.Client(url=url, token=token)
        self.__mount = mount
        # path for save last keys ID - default "last-key-id"
        self.last_id_path = "last-key-id"

    def get_last_kid(self) -> str:
        """Return last Key ID"""
        return self.__read(self.last_id_path)[0]["kid"]

    def load_keys(self, kid: str = "") -> tuple[str, dict]:
        """Load keys"""

        if kid == "":
            kid = self.get_last_kid()

        return kid, {"data": self.__read(kid)[0]}

    def save_keys(self, kid: str, keys: dict) -> None:
        """Save keys and set them as the last keys"""
        self.__write(kid, keys)
        self.save_last_kid(kid)

    def increase_counter(self, kid: str, limit: int = 0) -> int | None:
        """Atomically increase the counter of signed tokens of a key"""
        if self.kv_version == 1:
            return super().increase_counter(kid, limit)

        for _ in range(self.cas_attempts):
            keys, version = self.__read(kid)
            if limit and keys["counter"] >= limit:
                return None
            keys["counter"] += 1
            if self.__write_cas(kid, keys, version):
                return keys["counter"]
        raise KeysSaveError(f"Counter of the key '{kid}' was not saved.")

    def replace_last_keys(self, last_kid: str, kid: str, keys: dict) -> str:
        """Atomically save new keys as the last keys (key rotation)"""
        if self.kv_version == 1:
            return super().replace_last_keys(last_kid, kid, keys)

        for _ in range(self.cas_attempts):
            last, version = self.__read(self.last_id_path)
            if last["kid"] != last_kid:
                return last["kid"]
            # the new keys must exist before they become the last keys
            self.__write(kid, keys)
            if self.__write_cas(self.last_id_path, {"kid": kid}, version):
                return kid
            # another process changed the last Key ID, remove unused keys
            self.__client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=kid, mount_point=self.__mount
            )
        raise KeysSaveError("The last Key ID was not saved.")

    def update_metadata(self, kid: str, metadata: dict) -> None:
        """Atomically update metadata fields of a key record"""
        if self.kv_version == 1:
            super().update_metadata(kid, metadata)
            return

        for _ in range(self.cas_attempts):
            keys, version = self.__read(kid)
            keys.update(metadata)
            if self.__write_cas(kid, keys, version):
                return
        raise KeysSaveError(f"Metadata of the key '{kid}' were not saved.")

    def list_kids(self) -> list[str]:
        """
        Return Key IDs of all keys in the storage

        The Vault policy needs the 'list' capability, KV v2:
        '<mount>/metadata/*', KV v1: '<mount>/*'.
        """
        if self.kv_version == 1:
            result = self.__client.secrets.kv.v1.list_secrets(
                path="", mount_point=self.__mount
            )
        else:
            result = self.__client.secrets.kv.v2.list_secrets(
                path="", mount_point=self.__mount
            )
        return sorted(k for k in result["data"]["keys"] if is_valid_kid(k))

    def revoke_jti(self, jti: str, expires_at: int) -> None:
        """Save a revoked token ID to revoked/<digest>"""
        self.__write(f"revoked/{jti_digest(jti)}", {"exp": expires_at})

    def is_jti_revoked(self, jti: str) -> bool:
        """Return True when the token ID is revoked (one read)"""
        try:
            self.__read(f"revoked/{jti_digest(jti)}")
        except self.__invalid_path:
            return False
        return True

    def prune_revoked(self, now: int) -> int:
        """
        Delete records of revoked tokens which expired before 'now'

        Needs the 'list' and 'delete' capabilities on
        ``<mount>/metadata/*`` (KV v2).
        """
        try:
            if self.kv_version == 1:
                result = self.__client.secrets.kv.v1.list_secrets(
                    path="revoked", mount_point=self.__mount
                )
            else:
                result = self.__client.secrets.kv.v2.list_secrets(
                    path="revoked", mount_point=self.__mount
                )
        except self.__invalid_path:
            return 0
        deleted = 0
        for name in result["data"]["keys"]:
            path = f"revoked/{name}"
            try:
                record, _ = self.__read(path)
            except self.__invalid_path:
                # deleted by another process in the meantime
                continue
            if record["exp"] < now:
                self.__delete(path)
                deleted += 1
        return deleted

    def __delete(self, path: str) -> None:
        """Delete a secret (all versions)"""
        if self.kv_version == 1:
            self.__client.secrets.kv.v1.delete_secret(
                path=path, mount_point=self.__mount
            )
        else:
            self.__client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path, mount_point=self.__mount
            )

    def delete_keys(self, kid: str) -> None:
        """Delete keys (all versions) from the storage"""
        if not is_valid_kid(kid):
            raise ValueError(f"Invalid Key ID '{kid}'.")
        if self.kv_version == 1:
            self.__client.secrets.kv.v1.delete_secret(
                path=kid, mount_point=self.__mount
            )
        else:
            self.__client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=kid, mount_point=self.__mount
            )

    def save_last_kid(self, kid: str) -> None:
        """Save last Key ID"""
        self.__write(self.last_id_path, {"kid": kid})

    def __read(self, path: str) -> tuple[dict, int]:
        """Read a secret, return data and version (0 for KV v1)"""
        if self.kv_version == 1:
            result = self.__client.secrets.kv.v1.read_secret(
                path=path, mount_point=self.__mount
            )
            return result["data"], 0

        result = self.__client.secrets.kv.v2.read_secret_version(
            path=path,
            mount_point=self.__mount,
            raise_on_deleted_version=True,
        )
        return result["data"]["data"], result["data"]["metadata"]["version"]

    def __write(self, path: str, secret: dict) -> None:
        """Write a secret without check-and-set"""
        if self.kv_version == 1:
            self.__client.secrets.kv.v1.create_or_update_secret(
                mount_point=self.__mount, path=path, secret=secret
            )
        else:
            self.__client.secrets.kv.v2.create_or_update_secret(
                mount_point=self.__mount, path=path, secret=secret
            )

    def __write_cas(self, path: str, secret: dict, version: int) -> bool:
        """
        Write a secret only if its version was not changed (KV v2)

        :returns: False when another process changed the secret
        """
        try:
            self.__client.secrets.kv.v2.create_or_update_secret(
                mount_point=self.__mount, path=path, secret=secret, cas=version
            )
        except self.__invalid_request as e:
            if "check-and-set" in str(e):
                return False
            raise
        return True


def import_hvac() -> Any:
    """
    Import hvac (the Vault client), an optional dependency since 1.0.0

    :raises ImportError: hvac is not installed
    """
    try:
        import hvac  # pylint: disable=import-outside-toplevel
    except ImportError as e:
        raise ImportError(
            "StorageVault requires hvac: pip install joserfc-wrapper[vault]"
        ) from e
    return hvac
