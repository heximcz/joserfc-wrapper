"""
Contract checks of a key storage, for tests of custom storages

Plain functions with assert, no test framework is needed::

    from joserfc_wrapper.testing import check_storage

    def test_my_storage():
        check_storage(MyStorage(...))

The checks create their own keys with new Key IDs, the storage does not
have to be empty (e.g. a shared test mount of Vault). They change the last
Key ID of the storage, never run them against a production storage.
"""

import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from joserfc_wrapper.abstract_key_storage import AbstractKeyStorage
from joserfc_wrapper.wrap_jwk import WrapJWK
from joserfc_wrapper.wrap_jwt import WrapJWT

THREADS = 4
INCREMENTS = 10


def check_storage(storage: AbstractKeyStorage, atomic: bool = True) -> None:
    """
    Run all checks supported by the storage

    Verification keys and their cache are always checked. Listing and
    deleting keys, JWKS and token revocation are checked only when the
    storage implements them.

    :param storage: storage to check
    :param atomic: check concurrent changes ('increase_counter',
        'replace_last_keys'), False for storages which are not safe for
        concurrent processes
    :raises AssertionError: the storage breaks the contract
    """
    check_keys(storage)
    check_verification_keys(storage)
    check_counter(storage)
    check_metadata(storage)
    check_replace_last_keys(storage)
    check_tokens(storage)
    if atomic:
        check_concurrent_counter(storage)
    if supports_listing(storage):
        check_list_and_delete(storage)
        check_jwks(storage)
    if storage.supports_token_revocation():
        check_token_revocation(storage)


def new_record(counter: int = 0) -> dict:
    """Key record like WrapJWK saves it (keys are not real keys)"""
    return {
        "keys": {"private": {"x": 1}, "public": {"x": 2}, "secret": {"x": 3}},
        "counter": counter,
        "created": int(time.time()),
        "retired": None,
        "revoked": None,
    }


def save_new_keys(storage: AbstractKeyStorage, counter: int = 0) -> str:
    """Save a new record as the last keys, return its Key ID"""
    kid = uuid.uuid4().hex
    storage.save_keys(kid, new_record(counter))
    return kid


def check_keys(storage: AbstractKeyStorage) -> None:
    """save_keys, load_keys and get_last_kid"""
    kid = save_new_keys(storage)
    assert storage.get_last_kid() == kid, "save_keys sets the last Key ID"

    loaded_kid, stored = storage.load_keys()
    assert loaded_kid == kid, "load_keys() loads the last keys"
    expected = {**new_record(), "created": stored["data"]["created"]}
    assert stored == {"data": expected}, "load_keys returns {'data': record}"

    other = save_new_keys(storage)
    assert storage.load_keys(kid)[0] == kid, "load_keys(kid) loads the kid"
    assert storage.get_last_kid() == other
    storage.save_last_kid(kid)
    assert storage.get_last_kid() == kid, "save_last_kid sets the last kid"
    storage.save_last_kid(other)

    missing = uuid.uuid4().hex
    try:
        storage.load_keys(missing)
    except Exception as e:  # pylint: disable=broad-exception-caught
        # 'not_found_errors' is optional, KeysNotFoundError needs it
        assert not storage.not_found_errors or isinstance(
            e, storage.not_found_errors
        ), (
            "missing keys raise an error of 'not_found_errors', got "
            f"{type(e).__name__}"
        )
    else:
        raise AssertionError("load_keys of a missing Key ID must raise")


def check_verification_keys(storage: AbstractKeyStorage) -> None:
    """load_verification_key (cached) and clear_key_cache"""
    kid = save_new_keys(storage)

    public, revoked = storage.load_verification_key(kid)
    assert public == new_record()["keys"]["public"], "the public key"
    assert revoked is None

    storage.update_metadata(kid, {"revoked": 123})
    storage.clear_key_cache(kid)
    assert storage.load_verification_key(kid)[1] == 123, "revoked after clear"

    missing = uuid.uuid4().hex
    try:
        storage.load_verification_key(missing)
    except Exception as e:  # pylint: disable=broad-exception-caught
        assert not storage.not_found_errors or isinstance(
            e, storage.not_found_errors
        ), f"missing keys raise 'not_found_errors', got {type(e).__name__}"
    else:
        raise AssertionError("a missing Key ID must raise")


def check_counter(storage: AbstractKeyStorage) -> None:
    """increase_counter with and without a limit"""
    kid = save_new_keys(storage)
    last = save_new_keys(storage)

    assert storage.increase_counter(kid) == 1
    assert storage.increase_counter(kid, limit=2) == 2
    assert storage.increase_counter(kid, limit=2) is None, "limit reached"
    assert storage.load_keys(kid)[1]["data"]["counter"] == 2
    assert storage.get_last_kid() == last, "the last Key ID is not changed"


def check_metadata(storage: AbstractKeyStorage) -> None:
    """update_metadata keeps other fields and the last Key ID"""
    kid = save_new_keys(storage, counter=5)
    last = save_new_keys(storage)

    storage.update_metadata(kid, {"retired": 123})
    storage.increase_counter(kid)

    data = storage.load_keys(kid)[1]["data"]
    assert data["retired"] == 123
    assert data["counter"] == 6, "update_metadata keeps the counter"
    assert data["keys"] == new_record()["keys"]
    assert storage.get_last_kid() == last


def check_replace_last_keys(storage: AbstractKeyStorage) -> None:
    """replace_last_keys saves the keys only when the last kid matches"""
    first = save_new_keys(storage)
    second, third = uuid.uuid4().hex, uuid.uuid4().hex

    assert storage.replace_last_keys(first, second, new_record()) == second
    assert storage.get_last_kid() == second
    # another process already rotated the keys
    assert storage.replace_last_keys(first, third, new_record()) == second
    assert storage.get_last_kid() == second


def check_tokens(storage: AbstractKeyStorage) -> None:
    """WrapJWK and WrapJWT work with the storage"""
    jwk = WrapJWK(storage)
    jwk.rotate()
    jwt = WrapJWT(jwk, issuer="https://example.com", audience="api")
    token = jwt.create({"uid": 1}, exp=60)
    jwk.rotate()

    assert jwt.verify(token).claims["uid"] == 1, "retired keys still verify"
    assert jwt.verify(jwt.create({"uid": 2}, exp=60)).claims["uid"] == 2


def check_concurrent_counter(storage: AbstractKeyStorage) -> None:
    """increase_counter from concurrent threads loses no increment"""
    kid = save_new_keys(storage)

    def increase(_: int) -> None:
        for _ in range(INCREMENTS):
            storage.increase_counter(kid)

    with ThreadPoolExecutor(THREADS) as pool:
        list(pool.map(increase, range(THREADS)))

    counter = storage.load_keys(kid)[1]["data"]["counter"]
    assert counter == THREADS * INCREMENTS, f"lost increments: {counter}"


def supports_listing(storage: AbstractKeyStorage) -> bool:
    """Return True when the storage implements list_kids"""
    try:
        storage.list_kids()
    except NotImplementedError:
        return False
    return True


def check_list_and_delete(storage: AbstractKeyStorage) -> None:
    """list_kids and delete_keys"""
    kid = save_new_keys(storage)
    last = save_new_keys(storage)

    kids = storage.list_kids()
    assert kid in kids and last in kids, "list_kids lists all keys"
    assert "last-key-id" not in kids

    storage.delete_keys(kid)
    assert kid not in storage.list_kids()
    assert storage.get_last_kid() == last
    try:
        storage.delete_keys("../last-key-id")
    except ValueError:
        pass
    else:
        raise AssertionError("delete_keys must refuse an invalid Key ID")


def check_jwks(storage: AbstractKeyStorage) -> None:
    """load_jwks: all keys except revoked keys, no private keys"""
    kid = save_new_keys(storage)
    revoked = save_new_keys(storage)
    storage.update_metadata(revoked, {"revoked": 123})
    storage.clear_key_cache(revoked)

    keys = {key["kid"]: key for key in storage.load_jwks()["keys"]}

    assert kid in keys, "the JWKS contains the keys"
    assert revoked not in keys, "the JWKS does not contain revoked keys"
    assert keys[kid]["use"] == "sig" and keys[kid]["alg"] == "ES256"
    for key in keys.values():
        assert "d" not in key and "private" not in key, "no private keys"


def check_read_only_storage(storage: AbstractKeyStorage, kid: str) -> None:
    """
    Checks of a storage which only verifies tokens (e.g. StorageJWKS)

    :param storage: storage to check
    :param kid: Key ID of a valid key in the storage
    :raises AssertionError: the storage breaks the contract
    """
    public, revoked = storage.load_verification_key(kid)
    assert public.get("kty") and "d" not in public, "a public key"
    assert revoked is None or isinstance(revoked, int)
    assert any(key["kid"] == kid for key in storage.load_jwks()["keys"])

    missing = uuid.uuid4().hex
    try:
        storage.load_verification_key(missing)
    except Exception as e:  # pylint: disable=broad-exception-caught
        assert isinstance(e, storage.not_found_errors), (
            "missing keys raise an error of 'not_found_errors', got "
            f"{type(e).__name__}"
        )
    else:
        raise AssertionError("a missing Key ID must raise")

    for call in (
        storage.get_last_kid,
        lambda: storage.save_keys(missing, new_record()),
    ):
        try:
            call()
        except NotImplementedError:
            pass
        else:
            raise AssertionError("a read-only storage refuses writes")
    assert not storage.supports_token_revocation()


def check_token_revocation(storage: AbstractKeyStorage) -> None:
    """revoke_jti, is_jti_revoked and prune_revoked"""
    now = int(time.time())
    jti, other = uuid.uuid4().hex, uuid.uuid4().hex

    storage.revoke_jti(jti, now + 3600)
    assert storage.is_jti_revoked(jti)
    assert not storage.is_jti_revoked(other)
    # any string, not only uuid4 hex (tokens of other issuers)
    storage.revoke_jti("../odd jti/*", now + 3600)
    assert storage.is_jti_revoked("../odd jti/*")

    assert isinstance(storage.prune_revoked(now), int)
    assert storage.is_jti_revoked(jti), "not expired records are kept"
    # storages with automatic expiration (Redis) return 0
    if storage.prune_revoked(now + 7200):
        assert not storage.is_jti_revoked(jti), "expired records are deleted"
