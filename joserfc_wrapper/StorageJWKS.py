"""read-only storage of public keys from a JWK Set (JWKS)"""

import json
import threading
import time
from typing import Any
from urllib.parse import urlparse

import requests
from joserfc.jwk import ECKey

from joserfc_wrapper.AbstractKeyStorage import AbstractKeyStorage
from joserfc_wrapper.TokenHeader import is_valid_kid

READ_ONLY = (
    "StorageJWKS contains only public keys, it can only verify tokens "
    "(WrapJWT.verify, decode)."
)

# retry of the first download when no JWKS was loaded yet (seconds)
FIRST_RETRY_INTERVAL = 1


class JWKSKeyNotFoundError(LookupError):
    """The Key ID is not in the JWKS"""


class StorageJWKS(AbstractKeyStorage):
    """
    Read-only storage with the public keys from a JWK Set (RFC 7517),
    for services which only verify tokens

    The JWKS is published by the service which creates the tokens
    ('WrapJWK.jwks()' or 'genjw jwks'). The verifying service needs no
    access to the storage with the private keys. Only 'WrapJWT.verify' and
    'decode' work, creating tokens, key management and token revocation
    ('revocation=True') are not supported.
    """

    not_found_errors = (JWKSKeyNotFoundError,)

    def __init__(
        self,
        source: str,
        ttl: int = 300,
        refresh_interval: int = 60,
        max_stale: int = 3600,
        timeout: float = 5.0,
        session: requests.Session | None = None,
        allow_http: bool = False,
    ) -> None:
        """
        :param source: https:// URL of the JWKS (e.g.
            https://auth.example.com/.well-known/jwks.json), or a file path
            (or file:// URL)
        :param ttl: the JWKS is downloaded again after this number of
            seconds, a revoked key is rejected after it at the latest
        :param refresh_interval: a token with an unknown Key ID (e.g. new
            keys after a rotation) downloads the JWKS again, at most once in
            this number of seconds (protection of the source)
        :param max_stale: when the source is not available, the last
            downloaded JWKS is used at most this number of seconds after
            its download, then verify raises KeysLoadError
        :param timeout: timeout of the HTTP request in seconds
        :param session: requests.Session for proxies, own CA certificates
            ('session.verify') or authentication
        :param allow_http: allow a http:// URL, only for a trusted network
            (a changed JWKS allows anyone to create valid tokens)
        :raises ValueError: invalid source or parameters
        """
        for name, value in (
            ("ttl", ttl),
            ("refresh_interval", refresh_interval),
            ("max_stale", max_stale),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise ValueError(f"'{name}' must be an int >= 0.")
        if max_stale < ttl:
            raise ValueError("'max_stale' must be greater or equal to 'ttl'.")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError("'timeout' must be a number of seconds.")
        self.source = source
        self.ttl = ttl
        self.refresh_interval = refresh_interval
        self.max_stale = max_stale
        self.timeout = timeout
        self.__url, self.__path = self.__parse_source(source, allow_http)
        self.__session = session or requests.Session()
        self.__lock = threading.Lock()
        # kid -> public JWK of the last successful download
        self.__keys: dict[str, dict] | None = None
        # monotonic times of the last successful download and last attempt
        self.__fetched_at = 0.0
        self.__attempted_at: float | None = None
        self.__last_error: Exception | None = None

    def load_verification_key(self, kid: str) -> tuple[dict, int | None]:
        """
        Return the public key of a Key ID from the JWKS (revoked keys are
        not in the JWKS, so revoked is always None)

        :raises JWKSKeyNotFoundError: the Key ID is not in the JWKS
        :raises: download or format errors of the JWKS
        """
        keys = self.__current_keys(kid)
        if kid not in keys:
            raise JWKSKeyNotFoundError(f"Key ID '{kid}' is not in the JWKS.")
        return keys[kid], None

    def load_jwks(self) -> dict:
        """Return the loaded JWKS (e.g. to publish it again)"""
        keys = self.__current_keys()
        return {
            "keys": [
                {**public, "kid": kid, "use": "sig", "alg": "ES256"}
                for kid, public in keys.items()
            ]
        }

    def get_last_kid(self) -> str:
        """Not supported, the JWKS has no last keys"""
        raise NotImplementedError(READ_ONLY)

    def load_keys(self, kid: str = "") -> tuple[str, dict]:
        """Not supported, the JWKS has no private keys"""
        raise NotImplementedError(READ_ONLY)

    def save_keys(self, kid: str, keys: dict) -> None:
        """Not supported, read-only"""
        raise NotImplementedError(READ_ONLY)

    def _save_last_id(self, kid: str) -> None:
        """Not supported, read-only"""
        raise NotImplementedError(READ_ONLY)

    def __current_keys(self, kid: str | None = None) -> dict[str, dict]:
        """
        Return the keys, download the JWKS when it is older than ttl or
        does not contain kid (limited by refresh_interval)
        """
        with self.__lock:
            now = time.monotonic()
            expired = self.__keys is None or now - self.__fetched_at >= self.ttl
            unknown = (
                kid is not None
                and self.__keys is not None
                and kid not in self.__keys
            )
            interval = (
                FIRST_RETRY_INTERVAL
                if self.__keys is None
                else self.refresh_interval
            )
            if (expired or unknown) and (
                self.__attempted_at is None
                or now - self.__attempted_at >= interval
            ):
                self.__refresh(now)
            if self.__keys is None:
                raise RuntimeError(
                    f"JWKS '{self.source}' is not loaded: "
                    f"{type(self.__last_error).__name__}: {self.__last_error}"
                ) from self.__last_error
            if now - self.__fetched_at >= self.max_stale:
                raise RuntimeError(
                    f"JWKS '{self.source}' is older than max_stale "
                    f"({self.max_stale} s), the source is not available: "
                    f"{type(self.__last_error).__name__}: {self.__last_error}"
                ) from self.__last_error
            return self.__keys

    def __refresh(self, now: float) -> None:
        """Download the JWKS, keep the previous keys after a failure"""
        self.__attempted_at = now
        try:
            keys = self.__parse(self.__download())
        except Exception as e:  # pylint: disable=broad-exception-caught
            # the previous keys are used until max_stale
            self.__last_error = e
            return
        self.__keys = keys
        self.__fetched_at = now
        self.__last_error = None

    def __download(self) -> Any:
        if self.__url is not None:
            response = self.__session.get(self.__url, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        with open(self.__path, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def __parse(document: Any) -> dict[str, dict]:
        """
        Return kid -> public JWK of the ES256 signing keys of a JWKS

        Keys of other types or algorithms are ignored.

        :raises ValueError: invalid JWKS or a private key in it
        """
        if not isinstance(document, dict) or not isinstance(
            document.get("keys"), list
        ):
            raise ValueError("Invalid JWKS, expected {'keys': [...]}.")
        keys = {}
        for jwk in document["keys"]:
            if not isinstance(jwk, dict):
                raise ValueError("Invalid JWKS, a key is not an object.")
            if "d" in jwk:
                raise ValueError(
                    "The JWKS contains a private key, never publish it."
                )
            if (
                jwk.get("kty") != "EC"
                or jwk.get("crv") != "P-256"
                or jwk.get("use", "sig") != "sig"
                or jwk.get("alg", "ES256") != "ES256"
            ):
                continue
            kid = jwk.get("kid")
            if not isinstance(kid, str) or not is_valid_kid(kid):
                raise ValueError(f"Invalid Key ID in the JWKS: {kid!r}.")
            public = {k: jwk[k] for k in ("kty", "crv", "x", "y") if k in jwk}
            # raises for an invalid key
            ECKey.import_key(public)
            keys[kid] = public
        return keys

    @staticmethod
    def __parse_source(source: str, allow_http: bool) -> tuple[str | None, str]:
        """
        :returns: URL or None, file path
        :raises ValueError: unsupported source
        """
        if not isinstance(source, str) or not source:
            raise ValueError("'source' must be a URL or a file path.")
        scheme = urlparse(source).scheme.lower()
        if scheme == "https" or (scheme == "http" and allow_http):
            return source, ""
        if scheme == "http":
            raise ValueError(
                "A http:// JWKS can be changed on the way, use https:// "
                "or allow_http=True in a trusted network."
            )
        if scheme == "file":
            return None, urlparse(source).path
        if scheme == "" or len(scheme) == 1:
            # a path (a single letter is a Windows drive)
            return None, source
        raise ValueError(f"Unsupported JWKS source '{source}'.")
