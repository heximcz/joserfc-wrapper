#!/usr/bin/env python3
"""generate jwt for cli"""

import os
import sys
import fire
import datetime
import warnings
from typing import Optional, Dict, Any, NoReturn
from joserfc_wrapper import (
    AbstractKeyStorage,
    InvalidTokenError,
    StorageVault,
    StorageFile,
    StorageRedis,
    WrapJWK,
    WrapJWT,
)
from joserfc.jwt import Token


def fail(message: str) -> NoReturn:
    """Print error to stderr and exit with code 1"""
    print(message, file=sys.stderr)
    sys.exit(1)


def fail_exception(e: Exception) -> NoReturn:
    """Print exception to stderr and exit with code 1"""
    fail(f"{type(e).__name__}: {str(e)}")


def parse_duration(option: str, value: str) -> int:
    """
    Duration like "minutes=5" in seconds, units: seconds, minutes, hours,
    days, weeks
    """
    if "=" not in value:
        fail(f"Error: {option}={value} bad format.")
    unit, _, number = value.partition("=")
    valid_units = {"seconds", "minutes", "days", "hours", "weeks"}
    if unit not in valid_units:
        fail(
            f'Error: "{unit}" in {option} is not in valid units: '
            f"{valid_units}."
        )
    if not number.isdigit() or int(number) <= 0:
        fail(f"Error: {option}={value} value must be an integer greater zero.")
    return int(datetime.timedelta(**{unit: int(number)}).total_seconds())


def format_time(timestamp: int | None) -> str:
    """Unix timestamp as UTC date and time, '-' for None"""
    if timestamp is None:
        return "-"
    return datetime.datetime.fromtimestamp(
        timestamp, tz=datetime.timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")


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
            if kv_version == "1":
                print(
                    "Warning: KV v1 (VAULT_KV_VERSION=1) is deprecated and "
                    "will be removed in 1.0.0, move the keys to a KV v2 mount.",
                    file=sys.stderr,
                )
            self.__vault_kv_version = int(kv_version)
        elif storage == "file":
            var = os.environ.get("CERT_DIR")
            if var is None:
                fail("Missing var in environment for 'file' storage: CERT_DIR")
            self.__cert_dir = os.environ["CERT_DIR"]
        elif storage == "redis":
            if not os.environ.get("REDIS_URL"):
                fail(
                    "Missing var in environment for 'redis' storage: REDIS_URL"
                )
            self.__redis_url = os.environ["REDIS_URL"]
            self.__redis_prefix = os.environ.get("REDIS_PREFIX", "jwt:")
        else:
            fail(
                "Allowed value is: --storage='vault' (default), 'file' or "
                "'redis'"
            )

        # create storage object
        try:
            if self.storage == "vault":
                vault = StorageVault(
                    self.__vault_addr,
                    self.__vault_token,
                    self.__vault_mount,
                    kv_version=self.__vault_kv_version,
                )
                self.__storage: AbstractKeyStorage = vault
                self.__wjwk = WrapJWK(vault)
            elif self.storage == "file":
                if not os.path.exists(self.__cert_dir):
                    fail(f"Error: directory {self.__cert_dir} not exist.")
                self.__storage = StorageFile(self.__cert_dir)
                self.__wjwk = WrapJWK(self.__storage)
            elif self.storage == "redis":
                self.__storage = StorageRedis.from_url(
                    self.__redis_url, prefix=self.__redis_prefix
                )
                self.__wjwk = WrapJWK(self.__storage)
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
        max_key_age: str = "",
    ) -> str:
        # pylint: disable=C0301
        """
        Create new JWT token.

        Required arguments:
            --iss=<issuer>: str
            --aud=<audince>: str
            --uid=<id>: int
            --exp=<expire after>: str
        Optional arguments:
            --custom=<custom data>: dict
            --max-key-age=<rotate keys after>: str
            --payload=<signed key payload> (deprecated, use --max-key-age)
            examples:
                --exp="minutes=5" - valid units: "seconds=int" | "minutes=int" | "days=int" | "hours=int" | "weeks=int"
                --custom="{var1:value1,var2:value2}"
                --max-key-age="days=30"
        """
        # required claims
        claims: Dict[str, Any] = {
            "iss": iss,
            "aud": aud,
            "uid": uid,
        }

        # expiration is required, a token without exp is always invalid
        if not exp:
            fail(
                'Error: --exp is required, e.g. --exp="hours=1". '
                "A token without expiration is invalid."
            )
        expire = parse_duration("--exp", exp)
        key_age = (
            parse_duration("--max-key-age", max_key_age)
            if max_key_age
            else None
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
        if payload:
            print(
                "Warning: --payload is deprecated, use --max-key-age.",
                file=sys.stderr,
            )

        # ok do token
        try:
            wjwt = WrapJWT(self.__wjwk, max_key_age=key_age)
            with warnings.catch_warnings():
                # the warning about payload is printed above
                warnings.simplefilter("ignore", DeprecationWarning)
                return wjwt.create(claims=claims, payload=payload, exp=expire)
        except Exception as e:  # pylint: disable=W0718
            fail_exception(e)

    def keys(self) -> str:
        """
        Create new KEYS (the first keys, or rotate the keys: the previous
        keys are retired, tokens signed by them stay valid until they expire)
        """
        try:
            self.__wjwk.rotate()
            return (
                f"New keys has been saved in '{self.storage}' "
                f"storage with KID: '{self.__wjwk.get_kid()}'."
            )
        except Exception as e:  # pylint: disable=W0718
            fail_exception(e)

    def rotate(self) -> str:
        """
        Rotate the keys (the same as keys)
        """
        return self.keys()

    def list(self) -> str:
        """
        List all keys with their metadata (the storage must support listing,
        Vault needs the 'list' capability)
        """
        try:
            keys = self.__wjwk.list_keys()
        except Exception as e:  # pylint: disable=W0718
            fail_exception(e)
        lines = []
        for key in keys:
            kid, counter = key["kid"], key["counter"]
            created, retired, revoked = (
                format_time(key[field])
                for field in ("created", "retired", "revoked")
            )
            state = "last" if key["last"] else "retired"
            if key["revoked"] is not None:
                state = "revoked"
            lines.append(
                f"{kid}  {state:8} created: {created}  retired: {retired}  "
                f"revoked: {revoked}  tokens: {counter}"
            )
        return "\n".join(lines) if lines else "No keys in the storage."

    def revoke(self, kid: str, yes: bool = False) -> str:
        """
        Revoke keys, all tokens signed by them become invalid

        Required arguments:
            --kid=<key id>: str
        Optional arguments:
            --yes: revoke, without it only shows what would happen
        """
        try:
            self.__wjwk.load_keys(kid)
            last = kid == self.__storage.get_last_kid()
        except Exception as e:  # pylint: disable=W0718
            fail_exception(e)
        if not yes:
            fail(
                f"Key {kid} would be revoked, all tokens signed by it "
                f"({self.__wjwk.get_counter()} tokens) become invalid."
                + (" New keys would be generated." if last else "")
                + " Add --yes to revoke."
            )
        try:
            self.__wjwk.revoke(kid)
        except Exception as e:  # pylint: disable=W0718
            fail_exception(e)
        return f"Key {kid} has been revoked." + (
            " New keys have been generated." if last else ""
        )

    def prune(self, lifetime: str) -> str:
        """
        Delete keys which cannot sign any valid token anymore (retired longer
        than the longest lifetime of tokens)

        Required arguments:
            --lifetime=<max token lifetime>: str, e.g. --lifetime="hours=1",
              the longest expiration of tokens you create (--exp)
        """
        seconds = parse_duration("--lifetime", lifetime)
        try:
            deleted = self.__wjwk.prune(seconds)
        except Exception as e:  # pylint: disable=W0718
            fail_exception(e)
        if not deleted:
            return "No keys to delete."
        return "Deleted keys: " + ", ".join(deleted)

    def revoke_token(self, token: str) -> str:
        """
        Revoke a single token, it becomes invalid (check) until it expires.
        The storage must support it (file, vault, redis).

        Required arguments:
            --token=<jwt token>: str
        """
        try:
            WrapJWT(self.__wjwk, revocation=True).revoke_token(token)
        except Exception as e:  # pylint: disable=W0718
            fail_exception(e)
        return "Token has been revoked."

    def check(self, iss: str, aud: str, token: str) -> str:
        """
        Check validity of a token (and revocation of the token when the
        storage supports it)

        Required arguments:
            --iss=<issuer>: str
            --aud=<audience>: str
            --token=<jwt token>: str
        """
        try:
            WrapJWT(
                self.__wjwk,
                issuer=iss,
                audience=aud,
                revocation=self.__wjwk.supports_token_revocation(),
            ).verify(token)
        except InvalidTokenError as e:
            fail(f"Token is invalid. {type(e).__name__}: {str(e)}")
        except Exception as e:  # pylint: disable=W0718
            fail_exception(e)

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
