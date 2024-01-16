import os
import re
import json
from joserfc_wrapper import AbstractKeyStorage


class StorageFile(AbstractKeyStorage):
    def __init__(self, cert_dir: str = os.environ["CERT_DIR"]) -> None:
        """
        :param cert_dir: - by default from os.environ['CERT_DIR']
        :type str:
        """
        # path to the directory where the certificates are stored
        self.__cert_dir = cert_dir

    def get_last_kid(self) -> str:
        """Return last Key ID"""
        files = [f for f in os.listdir(self.__cert_dir) if f.endswith(".json")]
        files.sort(
            key=lambda x: os.path.getmtime(os.path.join(self.__cert_dir, x)),
            reverse=True,
        )

        if files:
            match = re.search(r"^([a-f0-9]{32})?\.json$", files[0])
            if match:
                return match.group(1)

    def load_keys(self, kid: str) -> tuple[str, dict]:
        """Load keys"""
        if not kid:
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
        with open(keys_path, "w") as f:
            json.dump(keys, f)

    def __load_key_files(self, kid: str) -> dict:
        """Loads key files from the specified directory"""

        keys_path = os.path.join(self.__cert_dir, f"{kid}.json")
        with open(keys_path, "r") as f:
            keys = json.load(f)

        return keys
