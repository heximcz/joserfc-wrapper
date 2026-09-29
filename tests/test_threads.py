"""One WrapJWK, WrapJWT and WrapJWE shared by threads (0.8.0)"""

from concurrent.futures import ThreadPoolExecutor

import pytest

from joserfc_wrapper import WrapJWE, WrapJWK, WrapJWT

THREADS = 8
TOKENS = 25


# payload is deprecated, it forces rotations during the test
@pytest.mark.filterwarnings("ignore:.payload. is deprecated:DeprecationWarning")
def test_shared_instances(storage):
    jwk = WrapJWK(storage)
    jwk.rotate()
    jwt = WrapJWT(jwk, issuer="https://example.com", audience="api")
    jwe = WrapJWE(jwk)

    def work(thread: int) -> list[tuple[int, str]]:
        results = []
        for i in range(TOKENS):
            uid = thread * TOKENS + i
            secret = jwe.encrypt(f"secret {uid}")
            token = jwt.create(
                {"sub": str(uid), "sec": secret}, exp=60, payload=7
            )
            verified = jwt.verify(token)
            # the token belongs to this call, not to another thread
            assert verified.claims["sub"] == str(uid)
            assert (
                jwe.decrypt(verified.claims["sec"]) == f"secret {uid}".encode()
            )
            results.append((uid, verified.header["kid"]))
        return results

    with ThreadPoolExecutor(THREADS) as pool:
        results = [r for rs in pool.map(work, range(THREADS)) for r in rs]

    assert sorted(uid for uid, _ in results) == list(range(THREADS * TOKENS))
    # every key signed at most 'payload' tokens, all tokens are counted
    kids = [kid for _, kid in results]
    for kid in set(kids):
        counter = storage.load_keys(kid)[1]["data"]["counter"]
        assert counter == kids.count(kid) <= 7
