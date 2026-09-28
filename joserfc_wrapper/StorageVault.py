"""vault manipulation class"""

import hvac
from hvac.exceptions import InvalidPath, InvalidRequest
from joserfc_wrapper.AbstractKeyStorage import AbstractKeyStorage
from joserfc_wrapper.Exceptions import KeysSaveError


class StorageVault(AbstractKeyStorage):
    """interface for saving and loading a key on the HashiCorp Vault system"""

    # attempts to write with check-and-set before giving up
    cas_attempts = 100

    not_found_errors = (InvalidPath,)

    def __init__(
        self,
        url: str = "",
        token: str = "",
        mount: str = "",
        kv_version: int = 2,
    ) -> None:
        """
        Handles for HashiCorp Vault Storage

        :param url: - Vault URL
        :param token: - Token
        :param mount: - Vault mount point
        :param kv_version: - version of the KV secrets engine, 2 (default)
            uses check-and-set and is safe for concurrent processes,
            1 is for keys saved by older versions and is not atomic
        :raises ValueError: unsupported kv_version
        """
        if kv_version not in (1, 2):
            raise ValueError("kv_version must be 1 or 2")
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
        self._save_last_id(kid)

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

    def _save_last_id(self, kid: str) -> None:
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
        except InvalidRequest as e:
            if "check-and-set" in str(e):
                return False
            raise
        return True
