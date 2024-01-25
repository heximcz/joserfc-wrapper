""" vault manipulation class """
import hvac
from joserfc_wrapper.AbstractKeyStorage import AbstractKeyStorage


class StorageVault(AbstractKeyStorage):
    """interface for saving and loading a key on the HashiCorp Vault system"""

    def __init__(
        self,
        url: str = "",
        token: str = "",
        mount: str = "",
    ) -> None:
        """
        Handles for HashiCorp Vault Storage

        :param url: - Vault URL
        :type str:
        :param token: - Token
        :type str:
        :param mount: - Vault mount point
        :type str:
        """
        self.url = url
        self.token = token
        self.mount = mount
        self.__client = hvac.Client(url=url, token=token)
        self.__mount = mount
        # path for save last keys ID - default "last-key-id"
        self.last_id_path = "last-key-id"

    def get_last_kid(self) -> str:
        """Return last Key ID"""

        result = self.__client.secrets.kv.v1.read_secret(
            path=self.last_id_path,
            mount_point=self.__mount,
        )

        return result["data"]["kid"]

    def load_keys(self, kid: str = "") -> tuple[str, dict]:
        """Load keys"""

        if kid == "":
            kid = self.get_last_kid()

        result = self.__client.secrets.kv.v1.read_secret(
            path=kid,
            mount_point=self.__mount,
        )

        return kid, result

    def save_keys(self, kid: str, keys: dict) -> None:
        """Save keys"""

        self.__client.secrets.kv.v1.create_or_update_secret(
            mount_point=self.__mount, path=kid, secret=keys
        )

        self._save_last_id(kid)

    def _save_last_id(self, kid: str) -> None:
        """Save last Key ID"""

        secret = {"kid": kid}

        self.__client.secrets.kv.v1.create_or_update_secret(
            mount_point=self.__mount, path=self.last_id_path, secret=secret
        )
