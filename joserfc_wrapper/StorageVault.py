import os
import hvac
from joserfc_wrapper import AbstractKeyStorage


class StorageVault(AbstractKeyStorage):
    def __init__(
        self,
        url: str = os.environ["VAULT_URL"],
        token: str = os.environ["VAULT_TOKEN"],
        mount: str = os.environ["VAULT_MOUNT"],
    ) -> None:
        """
        Handles for HashiCorp Vault Storage

        :param url: - by default from os.environ['VAULT_URL']
        :type str:
        :param token: - by defult from os.environ['VAULT_TOKEN']
        :type str:
        :param mount: - by default from os.environ["VAULT_MOUNT"]
        :type str:
        """
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

    def load_keys(self, kid: str = None) -> tuple[str, dict]:
        """Load keys"""

        if not kid:
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

        self.__save_last_id(kid)

    def __save_last_id(self, kid: str) -> None:
        """Save last Key ID"""

        secret = {"kid": kid}

        self.__client.secrets.kv.v1.create_or_update_secret(
            mount_point=self.__mount, path=self.last_id_path, secret=secret
        )
