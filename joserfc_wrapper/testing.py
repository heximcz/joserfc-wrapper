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
from joserfc_wrapper.wrap_jwk import WrapJWK, generate_keys
from joserfc_wrapper.wrap_jwt import WrapJWT

THREADS = 8


def check_storage(storage: AbstractKeyStorage) -> None:
    """
    Run all checks supported by the storage

    The required methods, verification keys and their cache and the
    atomicity of 'replace_last_keys' and 'update_metadata' (concurrent
    threads) are always checked. Listing and deleting keys, JWKS and token
    revocation are checked only when the storage implements them.

    :param storage: storage to check
    :raises AssertionError: the storage breaks the contract
    """
    check_keys(storage)
    check_verification_keys(storage)
    check_metadata(storage)
    check_replace_last_keys(storage)
    check_concurrent_rotation(storage)
    check_concurrent_metadata(storage)
    check_tokens(storage)
    if supports_listing(storage):
        check_list_and_delete(storage)
        check_jwks(storage)
    if storage.supports_token_revocation():
        check_token_revocation(storage)


def new_keys(algorithm: str = "ES256") -> tuple[str, dict]:
    """New keys (Key ID and record) like WrapJWK creates them"""
    return generate_keys(algorithm)


def save_new_keys(storage: AbstractKeyStorage, algorithm: str = "ES256") -> str:
    """Save new keys as the last keys, return the Key ID"""
    kid, record = new_keys(algorithm)
    storage.save_keys(kid, record)
    return kid


def check_keys(storage: AbstractKeyStorage) -> None:
    """save_keys, load_keys, get_last_kid and save_last_kid"""
    kid, record = new_keys()
    storage.save_keys(kid, record)
    assert storage.get_last_kid() == kid, "save_keys sets the last Key ID"

    loaded_kid, stored = storage.load_keys()
    assert loaded_kid == kid, "load_keys() loads the last keys"
    assert stored == {"data": record}, "load_keys returns {'data': record}"

    other = save_new_keys(storage)
    assert storage.load_keys(kid)[0] == kid, "load_keys(kid) loads the kid"
    assert storage.get_last_kid() == other
    storage.save_last_kid(kid)
    assert storage.get_last_kid() == kid, "save_last_kid sets the last kid"
    storage.save_last_kid(other)

    missing = new_keys()[0]
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
    kid, record = new_keys()
    storage.save_keys(kid, record)

    public, revoked = storage.load_verification_key(kid)
    assert public == record["keys"]["public"], "the public key"
    assert revoked is None

    storage.update_metadata(kid, {"revoked": 123})
    storage.clear_key_cache(kid)
    assert storage.load_verification_key(kid)[1] == 123, "revoked after clear"

    missing = new_keys()[0]
    try:
        storage.load_verification_key(missing)
    except Exception as e:  # pylint: disable=broad-exception-caught
        assert not storage.not_found_errors or isinstance(
            e, storage.not_found_errors
        ), f"missing keys raise 'not_found_errors', got {type(e).__name__}"
    else:
        raise AssertionError("a missing Key ID must raise")


def check_metadata(storage: AbstractKeyStorage) -> None:
    """update_metadata keeps other fields and the last Key ID"""
    kid, record = new_keys()
    storage.save_keys(kid, record)
    last = save_new_keys(storage)

    storage.update_metadata(kid, {"retired": 123})
    storage.update_metadata(kid, {"revoked": 456})

    data = storage.load_keys(kid)[1]["data"]
    assert data["retired"] == 123 and data["revoked"] == 456
    assert data["keys"] == record["keys"], "update_metadata keeps the keys"
    assert data["created"] == record["created"]
    assert storage.get_last_kid() == last, "the last Key ID is not changed"


def check_replace_last_keys(storage: AbstractKeyStorage) -> None:
    """replace_last_keys saves the keys only when the last kid matches"""
    first = save_new_keys(storage)
    (second, record), (third, other) = new_keys(), new_keys()

    assert storage.replace_last_keys(first, second, record) == second
    assert storage.get_last_kid() == second
    assert storage.load_keys()[1]["data"] == record
    # another process already rotated the keys
    assert storage.replace_last_keys(first, third, other) == second
    assert storage.get_last_kid() == second


def check_concurrent_rotation(storage: AbstractKeyStorage) -> None:
    """replace_last_keys from concurrent threads: only one rotation wins"""
    last = save_new_keys(storage)
    candidates = [new_keys() for _ in range(THREADS)]

    def rotate(candidate: tuple[str, dict]) -> str:
        return storage.replace_last_keys(last, candidate[0], candidate[1])

    with ThreadPoolExecutor(THREADS) as pool:
        results = list(pool.map(rotate, candidates))

    winners = [kid for kid, _ in candidates if kid in results]
    assert len(winners) == 1, f"one rotation wins, got {len(winners)}"
    assert set(results) == set(winners), "all threads see the winner"
    assert storage.get_last_kid() == winners[0]


def check_concurrent_metadata(storage: AbstractKeyStorage) -> None:
    """update_metadata from concurrent threads loses no field"""
    kid, record = new_keys()
    storage.save_keys(kid, record)

    def update(i: int) -> None:
        storage.update_metadata(kid, {f"field{i}": i})

    with ThreadPoolExecutor(THREADS) as pool:
        list(pool.map(update, range(THREADS)))

    data = storage.load_keys(kid)[1]["data"]
    lost = [i for i in range(THREADS) if data.get(f"field{i}") != i]
    assert not lost, f"lost updates of metadata: {lost}"
    assert data["keys"] == record["keys"]


def check_tokens(storage: AbstractKeyStorage) -> None:
    """WrapJWK and WrapJWT work with the storage (ES256 and Ed25519)"""
    jwk = WrapJWK(storage)
    jwt = WrapJWT(jwk, issuer="https://example.com", audience="api")
    tokens = []
    for algorithm in ("ES256", "Ed25519"):
        jwk.rotate(algorithm)
        tokens.append(jwt.create({"sub": algorithm}, exp=60))
    jwk.rotate()

    for token, sub in zip(tokens, ("ES256", "Ed25519")):
        assert jwt.verify(token).claims["sub"] == sub, "retired keys verify"
    assert jwt.verify(jwt.create({"sub": "1"}, exp=60)).claims["sub"] == "1"


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
    ed25519 = save_new_keys(storage, "Ed25519")
    revoked = save_new_keys(storage)
    storage.update_metadata(revoked, {"revoked": 123})
    storage.clear_key_cache(revoked)

    keys = {key["kid"]: key for key in storage.load_jwks()["keys"]}

    assert kid in keys and ed25519 in keys, "the JWKS contains the keys"
    assert revoked not in keys, "the JWKS does not contain revoked keys"
    assert keys[kid]["use"] == "sig" and keys[kid]["alg"] == "ES256"
    assert keys[ed25519]["alg"] == "Ed25519"
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

    missing, record = new_keys()
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
        lambda: storage.save_keys(missing, record),
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
