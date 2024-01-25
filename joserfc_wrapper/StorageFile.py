""" file manipulation class """
import os
import json
from joserfc_wrapper.AbstractKeyStorage import AbstractKeyStorage


class StorageFile(AbstractKeyStorage):
    """interface for saving and loading a key on the file system"""

    def __init__(self, cert_dir: str) -> None:
        """
        :param cert_dir: - path to the directory with certificates
        :type str:
        """
        self.__cert_dir = cert_dir
        # file name for save last keys ID - default "last-key-id"
        self.last_id_name = "last-key-id"

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

        return kid, self.__load_key_files(kid)

    def save_keys(self, kid: str, keys: dict) -> None:
        """Save keys to vault"""

        # must have 'data' key for HashiCorp Vault compatibility
        keys = {
            "data": {
                "keys": {
                    "private": keys["keys"]["private"],
                    "public": keys["keys"]["public"],
                    "secret": keys["keys"]["secret"],
                },
                "counter": keys["counter"],
            }
        }

        # Save the public and private key to a files
        keys_path = os.path.join(self.__cert_dir, f"{kid}.json")
        with open(keys_path, "w", encoding="utf-8") as f:
            json.dump(keys, f)

        self._save_last_id(kid)

    def __load_key_files(self, kid: str) -> dict:
        """Loads key files from the specified directory"""

        keys_path = os.path.join(self.__cert_dir, f"{kid}.json")
        with open(keys_path, "r", encoding="utf-8") as f:
            keys = json.load(f)

        return keys

    def _save_last_id(self, kid: str) -> None:
        """save last kid to file with last key"""
        last_key = {"kid": kid}
        keys_path = os.path.join(self.__cert_dir, f"{self.last_id_name}.json")
        with open(keys_path, "w", encoding="utf-8") as f:
            json.dump(last_key, f)
