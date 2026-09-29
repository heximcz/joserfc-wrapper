"""vault manipulation class"""

from typing import Any

from joserfc_wrapper.abstract_key_storage import (
    AbstractKeyStorage,
    KEY_CACHE_TTL,
)
from joserfc_wrapper.exceptions import KeysSaveError
from joserfc_wrapper.token_header import (
    is_valid_kid,
    jti_digest,
    require_valid_kid,
)


class StorageVault(AbstractKeyStorage):
    """
    Keys in HashiCorp Vault, the KV v2 secrets engine

    Requires the extra dependency: pip install joserfc-wrapper[vault]
    Writes use check-and-set, safe for concurrent processes.
    """

    # attempts to write with check-and-set before giving up
    cas_attempts = 100

    def __init__(
        self,
        url: str = "",
        token: str = "",
        mount: str = "",
        key_cache_ttl: int = KEY_CACHE_TTL,
    ) -> None:
        """
        :param url: Vault URL
        :param token: Vault token
        :param mount: the KV v2 mount with the keys
        :param key_cache_ttl: lifetime of cached verification keys in
            seconds (default 300, 0 = no cache), see
            'AbstractKeyStorage.load_verification_key'
        :raises ValueError: invalid key_cache_ttl
        :raises ImportError: hvac is not installed
            (pip install joserfc-wrapper[vault])
        """
        self.key_cache_ttl = key_cache_ttl
        hvac = import_hvac()
        self.__invalid_path = hvac.exceptions.InvalidPath
        self.__invalid_request = hvac.exceptions.InvalidRequest
        self.not_found_errors = (self.__invalid_path,)
        self.url = url
        self.mount = mount
        self.__client = hvac.Client(url=url, token=token)
        self.__kv = self.__client.secrets.kv.v2
        # path of the last Key ID
        self.last_id_path = "last-key-id"

    def get_last_kid(self) -> str:
        """Return the last Key ID"""
        return self.__read(self.last_id_path)[0]["kid"]

    def load_keys(self, kid: str = "") -> tuple[str, dict]:
        """Load a key record"""
        if kid == "":
            kid = self.get_last_kid()
        return kid, {"data": self.__read(require_valid_kid(kid))[0]}

    def save_keys(self, kid: str, keys: dict) -> None:
        """Save keys and set them as the last keys"""
        self.__write(require_valid_kid(kid), keys)
        self.save_last_kid(kid)

    def replace_last_keys(self, last_kid: str, kid: str, keys: dict) -> str:
        """Atomically save new keys as the last keys (key rotation)"""
        require_valid_kid(kid)
        for _ in range(self.cas_attempts):
            last, version = self.__read(self.last_id_path)
            if last["kid"] != last_kid:
                return last["kid"]
            # the new keys must exist before they become the last keys
            self.__write(kid, keys)
            if self.__write_cas(self.last_id_path, {"kid": kid}, version):
                return kid
            # another process changed the last Key ID, remove unused keys
            self.__delete(kid)
        raise KeysSaveError("The last Key ID was not saved.")

    def update_metadata(self, kid: str, metadata: dict) -> None:
        """Atomically update metadata fields of a key record"""
        require_valid_kid(kid)
        for _ in range(self.cas_attempts):
            keys, version = self.__read(kid)
            keys.update(metadata)
            if self.__write_cas(kid, keys, version):
                return
        raise KeysSaveError(f"Metadata of the key '{kid}' were not saved.")

    def list_kids(self) -> list[str]:
        """
        Return Key IDs of all keys in the storage

        The Vault policy needs the 'list' capability on
        ``<mount>/metadata/*``.
        """
        try:
            result = self.__kv.list_secrets(path="", mount_point=self.mount)
        except self.__invalid_path:
            # an empty mount
            return []
        return sorted(k for k in result["data"]["keys"] if is_valid_kid(k))

    def delete_keys(self, kid: str) -> None:
        """Delete keys (all versions) from the storage"""
        self.__delete(require_valid_kid(kid))

    def save_last_kid(self, kid: str) -> None:
        """Save the last Key ID"""
        self.__write(self.last_id_path, {"kid": require_valid_kid(kid)})

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
        ``<mount>/metadata/*``.
        """
        try:
            result = self.__kv.list_secrets(
                path="revoked", mount_point=self.mount
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
        self.__kv.delete_metadata_and_all_versions(
            path=path, mount_point=self.mount
        )

    def __read(self, path: str) -> tuple[dict, int]:
        """Read a secret, return data and version"""
        result = self.__kv.read_secret_version(
            path=path,
            mount_point=self.mount,
            raise_on_deleted_version=True,
        )
        return result["data"]["data"], result["data"]["metadata"]["version"]

    def __write(self, path: str, secret: dict) -> None:
        """Write a secret without check-and-set"""
        self.__kv.create_or_update_secret(
            mount_point=self.mount, path=path, secret=secret
        )

    def __write_cas(self, path: str, secret: dict, version: int) -> bool:
        """
        Write a secret only if its version was not changed

        :returns: False when another process changed the secret
        """
        try:
            self.__kv.create_or_update_secret(
                mount_point=self.mount, path=path, secret=secret, cas=version
            )
        except self.__invalid_request as e:
            if "check-and-set" in str(e):
                return False
            raise
        return True


def import_hvac() -> Any:
    """
    Import hvac (the Vault client), an optional dependency

    :raises ImportError: hvac is not installed
    """
    try:
        import hvac  # pylint: disable=import-outside-toplevel
    except ImportError as e:
        raise ImportError(
            "StorageVault requires hvac: pip install joserfc-wrapper[vault]"
        ) from e
    return hvac
