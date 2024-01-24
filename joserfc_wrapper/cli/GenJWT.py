#!/usr/bin/env python3
""" generate jwt for cli """
import os
import sys
import fire
import datetime
from datetime import timezone
from typing import Optional, Dict, Any
from joserfc_wrapper import StorageVault, StorageFile, WrapJWK, WrapJWT
from joserfc.jwt import Token


class GenerateJWT:
    """Generate JWT"""

    def __init__(self, storage: str = "vault") -> None:
        self.storage = storage
        if storage == "vault":
            env_vars = ["VAULT_ADDR", "VAULT_TOKEN", "VAULT_MOUNT"]
            if not all(var in os.environ for var in env_vars):
                print(
                    f"Missing var(s) in environment for 'vault' storage: "
                    f"{' or '.join(env_vars)}."
                )
                sys.exit(1)
            self.__vault_addr = os.environ["VAULT_ADDR"]
            self.__vault_token = os.environ["VAULT_TOKEN"]
            self.__vault_mount = os.environ["VAULT_MOUNT"]
        elif storage == "file":
            var = os.environ.get("CERT_DIR")
            if var is None:
                print("Missing var in environment for 'file' storage: CERT_DIR")
                sys.exit(1)
            self.__cert_dir = os.environ["CERT_DIR"]
        else:
            print("Allowed value is: --storage='vault' (default) or 'file'")
            sys.exit(1)

        # create storage object
        try:
            if self.storage == "vault":
                vault = StorageVault(
                    self.__vault_addr, self.__vault_token, self.__vault_mount
                )
                self.__wjwk = WrapJWK(vault)
            elif self.storage == "file":
                if not os.path.exists(self.__cert_dir):
                    print(f"Error: directory {self.__cert_dir} not exist.")
                    sys.exit(1)
                self.__wjwk = WrapJWK(StorageFile(self.__cert_dir))
        except Exception as e:  # pylint: disable=W0718
            print(f"Error: {type(e).__name__} : {str(e)}")
            sys.exit(1)

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
        claims = {
            "iss": iss,
            "aud": aud,
            "uid": uid,
        }

        # add expiration if exist
        if exp:
            # check format
            if "=" not in exp:
                return f"Error: --exp={exp} bad format."
            parts = exp.split("=")
            valid_units = {"seconds", "minutes", "days", "hours", "weeks"}
            # check valid units
            if not parts[0] in valid_units:
                return f'Error: "{parts[0]}" in --exp is not in valid units: {valid_units}.'
            # check neno zero value
            if int(parts[1]) <= 0:
                return f"Error: --exp={exp} value must be greater zero."
            # Compute expiration and add to claims
            kwargs = {parts[0]: int(parts[1])}
            claims["exp"] = datetime.datetime.now(
                tz=timezone.utc
            ) + datetime.timedelta(**kwargs)

        # add custom to claims if exist and is dict
        if custom:
            if not isinstance(custom, dict):
                return "Error: --custom must be a 'dict'."
            for key, value in custom.items():
                if key not in claims:
                    claims[key] = value

        # ok do token
        try:
            wjwt = WrapJWT(self.__wjwk)
            if payload:
                if not isinstance(payload, int):
                    return "Error: --payload must be a 'int'."
                if payload > 0:
                    return wjwt.create(claims=claims, payload=payload)
            else:
                return wjwt.create(claims=claims)
        except Exception as e:  # pylint: disable=W0718
            return f"{type(e).__name__}: {str(e)}"

        return ""

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
            return f"{type(e).__name__}: {str(e)}"

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
            if wjwt.validate(token=decoded_token, claims=claims):
                return "Token is valid."
        except Exception as e:  # pylint: disable=W0718
            return f"{type(e).__name__}: {str(e)}"

        return ""

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
            return f"{type(e).__name__}: {str(e)}"

        return ""


def run() -> None:
    fire.Fire(GenerateJWT)


if __name__ == "__main__":
    run()
