"""joserfc jwk wrapper"""

import time
from collections.abc import Callable
from functools import partial
from typing import TypeVar

from joserfc.jwk import ECKey, OctKey, OKPKey

from joserfc_wrapper.abstract_key_storage import AbstractKeyStorage
from joserfc_wrapper.algorithms import (
    DEFAULT_ALGORITHM,
    check_algorithm,
    key_algorithm,
)
from joserfc_wrapper.token_header import is_valid_kid
from joserfc_wrapper.exceptions import (
    ConfigurationError,
    GenerateKeysError,
    KeysLoadError,
    KeysNotFoundError,
    KeysSaveError,
    ObjectTypeError,
    WrapperErrors,
)

T = TypeVar("T")

# metadata fields of a key record (unix timestamps or None)
METADATA = ("created", "retired", "revoked")


def generate_keys(algorithm: str = DEFAULT_ALGORITHM) -> tuple[str, dict]:
    """
    Generate new keys: a signature key and a secret key for JWE

    The Key ID is the RFC 7638 thumbprint of the signature key.

    :returns: Key ID and the key record in the storage format
    :raises GenerateKeysError:
    """
    check_algorithm(algorithm)
    try:
        if algorithm == "Ed25519":
            key: ECKey | OKPKey = OKPKey.generate_key("Ed25519")
        else:
            key = ECKey.generate_key("P-256")
        record = {
            "keys": {
                "private": key.as_dict(private=True),
                "public": key.as_dict(private=False),
                "secret": OctKey.generate_key(128).as_dict(),
            },
            "created": int(time.time()),
        }
        return key.thumbprint(), record
    except Exception as e:
        raise GenerateKeysError from e


class WrapJWK:
    """
    Management of the signature keys in a storage

    Keeps no state, one WrapJWK can be shared by all threads of the
    application.
    """

    def __init__(self, storage: AbstractKeyStorage) -> None:
        """
        :param storage: Storage object
        :raises ObjectTypeError: storage is not AbstractKeyStorage
        """
        if not isinstance(storage, AbstractKeyStorage):
            raise ObjectTypeError
        self.__storage = storage

    @property
    def storage(self) -> AbstractKeyStorage:
        """The storage of the keys"""
        return self.__storage

    def rotate(self, algorithm: str = DEFAULT_ALGORITHM) -> str:
        """
        Generate new keys and save them as the last keys

        The previous last keys are marked as retired, tokens signed by them
        stay valid until they expire. Without any keys in the storage the
        first keys are created. After a concurrent rotation by another
        process its keys stay the last keys.

        :param algorithm: the algorithm of the new keys, ES256 (default)
            or Ed25519
        :returns: Key ID of the last keys
        :raises ConfigurationError: unsupported algorithm
        :raises KeysLoadError:
        :raises KeysSaveError:
        """
        check_algorithm(algorithm)
        last_kid = self.__last_kid()
        if last_kid is None:
            kid, record = generate_keys(algorithm)
            self.__call_storage(
                KeysSaveError, partial(self.__storage.save_keys, kid, record)
            )
            last_kid = self.__last_kid()
            if last_kid != kid:
                # another process created the first keys at the same time,
                # retire ours, so 'prune' deletes them later
                self.__call_storage(
                    KeysSaveError,
                    partial(
                        self.__storage.update_metadata,
                        kid,
                        {"retired": int(time.time())},
                    ),
                )
                return last_kid or kid
            return kid
        return self.__rotate(last_kid, algorithm)

    def reserve_signing_key(
        self,
        max_key_age: int | None = None,
        algorithm: str = DEFAULT_ALGORITHM,
    ) -> tuple[str, dict]:
        """
        Return the last keys for signing a token, used by 'WrapJWT.create'

        New keys are generated when the last keys are revoked or older than
        'max_key_age'. Concurrent processes rotate the keys only once.

        :param max_key_age: None = unlimited, otherwise the keys are
            rotated after this number of seconds since their creation
            (keys without the creation time are rotated)
        :param algorithm: the algorithm of new keys after a rotation
        :returns: Key ID and the private key (JWK dict)
        :raises KeysNotFoundError: there are no keys in the storage
        :raises KeysLoadError:
        :raises KeysSaveError: the storage failed or the keys were rotated
            by other processes too many times in a row
        """
        check_algorithm(algorithm)
        kid, data = self.__load_record("")
        # each attempt fails only when other processes rotated the keys
        # and the new keys reached a limit in the meantime
        for _ in range(100):
            if data.get("revoked") is None and not too_old(data, max_key_age):
                private = self.__part(data, "private")
                # an unsupported key (e.g. RSA in a custom storage)
                self.__call_storage(
                    KeysLoadError, partial(key_algorithm, private)
                )
                return kid, private
            self.__rotate(kid, algorithm)
            kid, data = self.__load_record("")
        raise KeysSaveError("Unable to reserve the keys, too many rotations.")

    def revoke(self, kid: str, algorithm: str | None = None) -> None:
        """
        Revoke keys, tokens signed by them are invalid ('verify' raises
        TokenKeyRevokedError)

        The keys stay in the storage with the time of revocation. When
        they are the last keys, new keys are generated first, so creating
        tokens continues. The revoked keys are deleted by 'prune' later.

        :param kid: Key ID
        :param algorithm: the algorithm of the new keys when the revoked
            keys are the last keys, default the algorithm of the revoked
            keys
        :raises KeysNotFoundError: the keys are not in the storage or an
            invalid Key ID
        :raises ConfigurationError: unsupported algorithm
        :raises KeysLoadError:
        :raises KeysSaveError:
        """
        check_kid(kid)
        _, data = self.__load_record(kid)
        if algorithm is None:
            algorithm = self.__call_storage(
                KeysLoadError,
                lambda: key_algorithm(self.__part(data, "public")),
            )
        check_algorithm(algorithm)
        if kid == self.__last_kid():
            self.__rotate(kid, algorithm)
        self.__call_storage(
            KeysSaveError,
            partial(
                self.__storage.update_metadata,
                kid,
                {"revoked": int(time.time())},
            ),
        )
        # verify in this process rejects the tokens immediately
        self.__storage.clear_key_cache(kid)

    def list_keys(self) -> list[dict]:
        """
        Return all keys in the storage with their metadata, sorted by the
        creation time (keys without it first), the last keys at the end

        Each item: kid, last (bool), algorithm, created, retired, revoked.
        The private keys are not returned.

        :raises KeysLoadError: storage error or the storage does not
            support listing keys
        """
        kids = self.__call_storage(KeysLoadError, self.__storage.list_kids)
        last_kid = self.__last_kid()
        items = []
        for kid in kids:
            try:
                _, data = self.__load_record(kid)
            except KeysNotFoundError:
                # deleted by another process ('prune') in the meantime
                continue
            algorithm = self.__call_storage(
                KeysLoadError,
                lambda data=data: key_algorithm(self.__part(data, "public")),
            )
            items.append(
                {
                    "kid": kid,
                    "last": kid == last_kid,
                    "algorithm": algorithm,
                    **{field: data.get(field) for field in METADATA},
                }
            )
        # the last keys are always at the end (keys created in the same second)
        return sorted(
            items, key=lambda item: (item["last"], item["created"] or 0)
        )

    def prune(self, max_token_lifetime: int, leeway: int = 0) -> list[str]:
        """
        Delete keys which cannot sign any valid token anymore

        A key is deleted when it is not the last key and more than
        'max_token_lifetime' (+ leeway) seconds passed since it was retired,
        so all tokens signed by it have expired. Keys which are not the last
        keys and were never retired (a concurrent creation of the first keys)
        get the retirement time now and are deleted by a later 'prune'. Keys
        without the retirement and the creation time (retired by versions
        older than 0.5.0) are never deleted. Run it from the application or
        cron, never automatically. Records of revoked tokens which expired
        are deleted too.

        :param max_token_lifetime: the longest lifetime of a token in
            seconds ('max_token_lifetime' of WrapJWT)
        :param leeway: tolerance of clocks in seconds
        :returns: Key IDs of deleted keys
        :raises ConfigurationError: invalid max_token_lifetime or leeway
        :raises KeysLoadError: storage error or the storage does not
            support listing keys
        :raises KeysSaveError: the keys were not deleted
        """
        for name, value, minimum in (
            ("max_token_lifetime", max_token_lifetime, 1),
            ("leeway", leeway, 0),
        ):
            # bool is a subclass of int
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < minimum
            ):
                raise ConfigurationError(
                    f"'{name}' must be an integer {minimum} or greater."
                )
        now = int(time.time())
        deleted = []
        for item in self.list_keys():
            retired = item["retired"]
            if item["last"]:
                continue
            if retired is None and item["created"] is not None:
                # not the last keys and never retired (keys of a concurrent
                # creation of the first keys): retire them now
                self.__call_storage(
                    KeysSaveError,
                    partial(
                        self.__storage.update_metadata,
                        item["kid"],
                        {"retired": now},
                    ),
                )
                continue
            if retired is None:
                continue
            if now > retired + max_token_lifetime + leeway:
                try:
                    self.__storage.delete_keys(item["kid"])
                except self.__storage.not_found_errors:
                    # deleted by another process in the meantime
                    continue
                except Exception as e:
                    raise KeysSaveError(f"{type(e).__name__}: {e}") from e
                self.__storage.clear_key_cache(item["kid"])
                deleted.append(item["kid"])
        # records of revoked tokens which expired (storages without TTL)
        if self.supports_token_revocation():
            self.__call_storage(
                KeysSaveError,
                partial(self.__storage.prune_revoked, now - leeway),
            )
        return deleted

    def jwks(self) -> dict:
        """
        Return the public keys as a JWK Set (RFC 7517) for other services
        which verify tokens, e.g. from an endpoint /.well-known/jwks.json

        Contains all keys in the storage except revoked keys (the last and
        the retired keys, tokens signed by them are valid until they
        expire), never the private keys or the JWE secret keys. New keys
        are included immediately after a rotation.

        :returns: {"keys": [{"kid", "kty", "crv", "x", ..., "use", "alg"}]}
        :raises KeysLoadError: storage error or the storage does not
            support listing keys (Vault needs the 'list' capability)
        """
        return self.__call_storage(KeysLoadError, self.__storage.load_jwks)

    def load_verification_key(self, kid: str) -> tuple[dict, int | None]:
        """
        Return the public key and the time of revocation of a key, cached
        by the storage ('key_cache_ttl'), used by 'WrapJWT.verify'

        :param kid: Key ID
        :returns: public key (JWK dict) and revoked (unix timestamp or None)
        :raises KeysNotFoundError: the keys do not exist in the storage
        :raises KeysLoadError: storage error or invalid keys
        """
        check_kid(kid)
        return self.__load(partial(self.__storage.load_verification_key, kid))

    def load_secret_key(self, kid: str = "") -> tuple[str, dict]:
        """
        Return the secret key for encrypted data (JWE), used by WrapJWE

        :param kid: Key ID, default the last keys
        :returns: Key ID and the secret key (JWK dict)
        :raises KeysNotFoundError: the keys do not exist in the storage
        :raises KeysLoadError: storage error or invalid keys
        """
        if kid:
            check_kid(kid)
        loaded_kid, data = self.__load_record(kid)
        return loaded_kid, self.__part(data, "secret")

    def supports_token_revocation(self) -> bool:
        """Return True when the storage can revoke single tokens (jti)"""
        return self.__storage.supports_token_revocation()

    def revoke_jti(self, jti: str, expires_at: int) -> None:
        """
        Save a revoked token ID until the token expires

        :param jti: token ID
        :param expires_at: 'exp' of the token (unix timestamp)
        :raises KeysSaveError: storage error or not supported
        """
        self.__call_storage(
            KeysSaveError,
            partial(self.__storage.revoke_jti, jti, expires_at),
        )

    def is_jti_revoked(self, jti: str) -> bool:
        """
        Return True when the token ID is revoked

        :param jti: token ID
        :raises KeysLoadError: storage error or not supported
        """
        return self.__call_storage(
            KeysLoadError, partial(self.__storage.is_jti_revoked, jti)
        )

    def __rotate(self, last_kid: str, algorithm: str) -> str:
        """
        Replace the last keys by new keys, mark them retired

        :returns: Key ID of the last keys, of another process after a
            concurrent rotation
        """
        kid, record = generate_keys(algorithm)
        result = self.__call_storage(
            KeysSaveError,
            partial(
                self.__storage.replace_last_keys,
                last_kid=last_kid,
                kid=kid,
                keys=record,
            ),
        )
        if result != kid:
            # another process already rotated the keys
            return result
        self.__call_storage(
            KeysSaveError,
            partial(
                self.__storage.update_metadata,
                last_kid,
                {"retired": record["created"]},
            ),
        )
        return kid

    def __last_kid(self) -> str | None:
        """Return the last Key ID, None without keys"""
        try:
            return self.__load(self.__storage.get_last_kid)
        except KeysNotFoundError:
            return None

    def __load_record(self, kid: str) -> tuple[str, dict]:
        """
        Load a key record (the 'data' part) from the storage

        :param kid: Key ID, "" = the last keys
        :raises KeysNotFoundError: the keys do not exist in the storage
        :raises KeysLoadError: storage error
        """
        loaded_kid, result = self.__load(
            partial(self.__storage.load_keys, kid=kid)
        )
        return loaded_kid, self.__call_storage(
            KeysLoadError, lambda: result["data"]
        )

    def __part(self, data: dict, part: str) -> dict:
        """
        A part of the keys of a record: private, public or secret

        :raises KeysLoadError: invalid record
        """
        return self.__call_storage(KeysLoadError, lambda: data["keys"][part])

    def __load(self, call: Callable[[], T]) -> T:
        """
        Call a loading method of the storage, wrap its errors

        :raises KeysNotFoundError: the keys do not exist in the storage
        :raises KeysLoadError: storage error
        """
        try:
            return call()
        except WrapperErrors:
            raise
        except self.__storage.not_found_errors as e:
            raise KeysNotFoundError(f"{type(e).__name__}: {e}") from e
        except Exception as e:
            raise KeysLoadError(f"{type(e).__name__}: {e}") from e

    @staticmethod
    def __call_storage(error: type[WrapperErrors], call: Callable[[], T]) -> T:
        """
        Call the storage, wrap its errors (file, Vault, custom storage)

        The original exception is available as '__cause__'.
        """
        try:
            return call()
        except WrapperErrors:
            raise
        except Exception as e:
            raise error(f"{type(e).__name__}: {e}") from e


def check_kid(kid: str) -> None:
    """
    A Key ID from outside (API, CLI) is never passed to a storage unchecked
    (file paths, Vault paths, Redis keys)

    :raises KeysNotFoundError: invalid Key ID, such keys cannot exist
    """
    if not is_valid_kid(kid):
        raise KeysNotFoundError(f"Invalid Key ID {kid!r}.")


def too_old(data: dict, max_key_age: int | None) -> bool:
    """The keys are older than max_key_age (or without the creation time)"""
    if max_key_age is None:
        return False
    created = data.get("created")
    return created is None or int(time.time()) - created >= max_key_age
