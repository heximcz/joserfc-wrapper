"""One WrapJWK, WrapJWT and WrapJWE shared by threads"""

from concurrent.futures import ThreadPoolExecutor

from joserfc_wrapper import WrapJWE, WrapJWK, WrapJWT

THREADS = 8
TOKENS = 25


def test_shared_instances(storage):
    jwk = WrapJWK(storage)
    jwk.rotate()
    jwt = WrapJWT(jwk, issuer="https://example.com", audience="api")
    jwe = WrapJWE(jwk)

    def work(thread: int) -> list[tuple[int, str]]:
        results = []
        for i in range(TOKENS):
            uid = thread * TOKENS + i
            # rotations during the test, WrapJWK keeps no state
            if i % 7 == 0:
                jwk.rotate("Ed25519" if thread % 2 else "ES256")
            secret = jwe.encrypt(f"secret {uid}")
            token = jwt.create({"sub": str(uid), "sec": secret}, exp=60)
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
    # tokens of all keys (also retired) stay valid
    kids = {kid for _, kid in results}
    assert kids <= set(storage.list_kids())
