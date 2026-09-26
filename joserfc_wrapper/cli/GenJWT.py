#!/usr/bin/env python3
"""generate jwt for cli"""

import os
import sys
import fire
import datetime
from typing import Optional, Dict, Any, NoReturn
from joserfc_wrapper import StorageVault, StorageFile, WrapJWK, WrapJWT
from joserfc.jwt import Token


def fail(message: str) -> NoReturn:
    """Print error to stderr and exit with code 1"""
    print(message, file=sys.stderr)
    sys.exit(1)


def fail_exception(e: Exception) -> NoReturn:
    """Print exception to stderr and exit with code 1"""
    fail(f"{type(e).__name__}: {str(e)}")


class GenerateJWT:
    """Generate JWT"""

    def __init__(self, storage: str = "vault") -> None:
        self.storage = storage
        if storage == "vault":
            env_vars = ["VAULT_ADDR", "VAULT_TOKEN", "VAULT_MOUNT"]
            if not all(var in os.environ for var in env_vars):
                names = " or ".join(env_vars)
                fail(
                    "Missing var(s) in environment for 'vault' storage: "
                    f"{names}."
                )
            self.__vault_addr = os.environ["VAULT_ADDR"]
            self.__vault_token = os.environ["VAULT_TOKEN"]
            self.__vault_mount = os.environ["VAULT_MOUNT"]
            kv_version = os.environ.get("VAULT_KV_VERSION", "2")
            if kv_version not in ("1", "2"):
                fail("VAULT_KV_VERSION must be 1 or 2 (default).")
            self.__vault_kv_version = int(kv_version)
        elif storage == "file":
            var = os.environ.get("CERT_DIR")
            if var is None:
                fail("Missing var in environment for 'file' storage: CERT_DIR")
            self.__cert_dir = os.environ["CERT_DIR"]
        else:
            fail("Allowed value is: --storage='vault' (default) or 'file'")

        # create storage object
        try:
            if self.storage == "vault":
                vault = StorageVault(
                    self.__vault_addr,
                    self.__vault_token,
                    self.__vault_mount,
                    kv_version=self.__vault_kv_version,
                )
                self.__wjwk = WrapJWK(vault)
            elif self.storage == "file":
                if not os.path.exists(self.__cert_dir):
                    fail(f"Error: directory {self.__cert_dir} not exist.")
                self.__wjwk = WrapJWK(StorageFile(self.__cert_dir))
        except Exception as e:  # pylint: disable=W0718
            fail_exception(e)

    def token(
        self,
        iss: str,
        aud: str,
        uid: int,
        exp: str = "",
        custom: Optional[Dict[Any, Any]] = None,
        payload: int = 0,
    ) -> str:
        # pylint: disable=C0301
        """
        Create new JWT token.

        Required arguments:
            --iss=<issuer>: str
            --aud=<audince>: str
            --uid=<id>: int
        Optional arguments:
            --exp=<expire after>: str
            --custom=<custom data>: dict
            --payload=<signed key payload>
            examples:
                --exp="minutes=5" - valid units: "seconds=int" | "minutes=int" | "days=int" | "hours=int" | "weeks=int"
                --custom="{var1:value1,var2:value2}"
                --payload=5
        """
        # required claims
        claims: Dict[str, Any] = {
            "iss": iss,
            "aud": aud,
            "uid": uid,
        }

        # add expiration if exist
        expire = None
        if exp:
            # check format
            if "=" not in exp:
                fail(f"Error: --exp={exp} bad format.")
            unit, _, value = exp.partition("=")
            valid_units = {"seconds", "minutes", "days", "hours", "weeks"}
            # check valid units
            if unit not in valid_units:
                fail(
                    f'Error: "{unit}" in --exp is not in valid units: '
                    f"{valid_units}."
                )
            # check integer value greater zero
            if not value.isdigit() or int(value) <= 0:
                fail(
                    f"Error: --exp={exp} value must be an integer greater zero."
                )
            # expiration in seconds
            expire = int(
                datetime.timedelta(**{unit: int(value)}).total_seconds()
            )

        # add custom to claims if exist and is dict
        if custom:
            if not isinstance(custom, dict):
                fail("Error: --custom must be a 'dict'.")
            for key, value in custom.items():
                if key not in claims:
                    claims[key] = value

        # bool is a subclass of int
        if not isinstance(payload, int) or isinstance(payload, bool):
            fail("Error: --payload must be a 'int'.")
        if payload < 0:
            fail("Error: --payload must be zero (unlimited) or greater.")

        # ok do token
        try:
            wjwt = WrapJWT(self.__wjwk)
            return wjwt.create(claims=claims, payload=payload, exp=expire)
        except Exception as e:  # pylint: disable=W0718
            fail_exception(e)

    def keys(self) -> str:
        """
        Create new KEYS
        """
        try:
            # create new keys
            self.__wjwk.generate_keys()
            self.__wjwk.save_keys()
            return (
                f"New keys has been saved in '{self.storage}' "
                f"storage with KID: '{self.__wjwk.get_kid()}'."
            )
        except Exception as e:  # pylint: disable=W0718
            fail_exception(e)

    def check(self, iss: str, aud: str, token: str) -> str:
        """
        Check validity of a token

        Required arguments:
            --iss=<issuer>: str
            --aud=<audience>: str
            --token=<jwt token>: str
        """
        # required claims
        claims = {
            "iss": iss,
            "aud": aud,
        }

        try:
            wjwt = WrapJWT(self.__wjwk)
            decoded_token: Token = wjwt.decode(token=token)
            valid = wjwt.validate(token=decoded_token, claims=claims)
        except Exception as e:  # pylint: disable=W0718
            fail_exception(e)

        if not valid:
            fail("Token is invalid.")
        return "Token is valid."

    def show(
        self, token: str, header: bool = False, claims: bool = True
    ) -> str:
        """
        Show headers and claims from a token

        Required arguments:
            --token=<jwt token>: str
        Optional arguments:
            --header=True: bool - default False
            --claims=False: bool - default True
        """
        try:
            wjwt = WrapJWT(self.__wjwk)
            decoded_token: Token = wjwt.decode(token=token)
            if header:
                print(f"Header: {decoded_token.header}")
            if claims:
                print(f"Claims: {decoded_token.claims}")
        except Exception as e:  # pylint: disable=W0718
            fail_exception(e)

        return ""


def run() -> None:
    fire.Fire(GenerateJWT)


if __name__ == "__main__":
    run()
