"""Fixes of the code audit of 1.0.0"""

import json
import os
import threading
import time
from unittest.mock import MagicMock, patch

import fakeredis
import pytest
from hvac.exceptions import InvalidPath
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import ECKey

from joserfc_wrapper import (
    CreateTokenError,
    KeysLoadError,
    KeysNotFoundError,
    StorageFile,
    StorageJWKS,
    StorageRedis,
    StorageVault,
    TokenExpiredError,
    WrapJWE,
    WrapJWK,
    WrapJWT,
)
from joserfc_wrapper.cli.gen_jwt import (
    GenerateJWT,
    keep_strings,
    parse_duration,
    run,
)
from joserfc_wrapper.wrap_jwk import generate_keys

from .conftest import key_part, last_kid

URL_JWKS = "https://auth.example/jwks.json"
TRAVERSAL = ["../outside/victim", "last-key-id", "revoked/x", "", "a/b"]


@pytest.fixture
def victim(tmp_path) -> str:
    """A JSON file outside of the key directory"""
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    path = outside / "victim.json"
    record = {"data": {"keys": {"private": {}, "public": {}, "secret": {}}}}
    path.write_text(json.dumps(record))
    return str(path)


# 1 Key IDs from outside are validated


@pytest.mark.parametrize("kid", [k for k in TRAVERSAL if k])
def test_wrapjwk_refuses_invalid_kid(jwk, kid):
    with pytest.raises(KeysNotFoundError, match="Invalid Key ID"):
        jwk.revoke(kid)
    with pytest.raises(KeysNotFoundError, match="Invalid Key ID"):
        jwk.load_verification_key(kid)
    with pytest.raises(KeysNotFoundError, match="Invalid Key ID"):
        jwk.load_secret_key(kid)
    with pytest.raises(KeysNotFoundError, match="Invalid Key ID"):
        WrapJWE(jwk).decrypt(WrapJWE(jwk).encrypt("x"), kid=kid)


def test_revoke_does_not_write_outside(jwk, tmp_path, victim):
    before = open(victim, encoding="utf-8").read()
    relative = os.path.relpath(victim, tmp_path)[: -len(".json")]

    with pytest.raises(KeysNotFoundError):
        jwk.revoke(relative)

    assert open(victim, encoding="utf-8").read() == before


def test_cli_revoke_refuses_invalid_kid(jwk, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CERT_DIR", str(tmp_path))

    with pytest.raises(SystemExit):
        GenerateJWT(storage="file").revoke(kid="../x", yes=True)
    assert "Invalid Key ID" in capsys.readouterr().err


def storages(tmp_path) -> list:
    with patch("hvac.Client"):
        vault = StorageVault("url", "token", "mount")
    return [
        StorageFile(str(tmp_path)),
        StorageRedis(fakeredis.FakeRedis()),
        vault,
    ]


@pytest.mark.parametrize("index", [0, 1, 2], ids=["file", "redis", "vault"])
@pytest.mark.parametrize("kid", TRAVERSAL[:3])
def test_storages_refuse_invalid_kid(tmp_path, index, kid):
    storage = storages(tmp_path)[index]
    _, record = generate_keys()

    for call in (
        lambda: storage.load_keys(kid),
        lambda: storage.save_keys(kid, record),
        lambda: storage.save_last_kid(kid),
        lambda: storage.replace_last_keys(generate_keys()[0], kid, record),
        lambda: storage.update_metadata(kid, {"revoked": 1}),
        lambda: storage.delete_keys(kid),
    ):
        with pytest.raises(ValueError, match="Invalid Key ID"):
            call()


# 2 concurrent deletion of keys


def test_list_keys_skips_deleted_keys(jwk, storage, tmp_path):
    first = last_kid(jwk)
    jwk.rotate()
    original = storage.list_kids

    def listed() -> list[str]:
        kids = original()
        (tmp_path / f"{first}.json").unlink()
        return kids

    with patch.object(storage, "list_kids", side_effect=listed):
        assert first not in [k["kid"] for k in jwk.list_keys()]


def test_prune_key_deleted_by_another_process(jwk, storage):
    first = last_kid(jwk)
    jwk.rotate()
    original = storage.delete_keys

    def concurrent(kid: str) -> None:
        original(kid)
        # the other process was faster
        raise FileNotFoundError(kid)

    with patch("time.time", return_value=time.time() + 3602):
        with patch.object(storage, "delete_keys", side_effect=concurrent):
            assert jwk.prune(max_token_lifetime=3600) == []
    assert first not in storage.list_kids()


# 3 JWKS redirected to http


def jwks_session(url: str, document: dict) -> MagicMock:
    session = MagicMock()
    session.get.return_value.json.return_value = document
    session.get.return_value.url = url
    return session


def test_jwks_redirect_to_http_is_refused(jwk):
    session = jwks_session("http://evil.example/jwks.json", jwk.jwks())
    storage = StorageJWKS("https://auth.example/jwks.json", session=session)

    with pytest.raises(KeysLoadError, match="redirected to http"):
        WrapJWK(storage).load_verification_key(last_kid(jwk))


def test_jwks_redirect_to_http_with_allow_http(jwk):
    session = jwks_session("http://auth.internal/jwks.json", jwk.jwks())
    storage = StorageJWKS(
        "https://auth.example/jwks.json", session=session, allow_http=True
    )

    public, _ = WrapJWK(storage).load_verification_key(last_kid(jwk))
    assert public["kty"] == "EC"


# 4, 5 unsupported keys in a custom storage


def rsa_record() -> dict:
    key = {"kty": "RSA", "n": "x", "e": "AQAB"}
    return {
        "keys": {"private": {**key, "d": "y"}, "public": key, "secret": {}},
        "created": int(time.time()),
    }


def test_create_with_unsupported_key(storage):
    storage.save_keys("A" * 43, rsa_record())

    with pytest.raises(KeysLoadError, match="Unsupported key"):
        WrapJWT(WrapJWK(storage)).create({"iss": "i", "aud": "a", "sub": "1"})


def test_jwks_skips_unsupported_keys(jwk, storage):
    kid = last_kid(jwk)
    storage.save_keys("A" * 43, rsa_record())
    storage.save_last_kid(kid)

    assert [k["kid"] for k in jwk.jwks()["keys"]] == [kid]


# 6 NumericDate claims of create


@pytest.mark.parametrize(
    "claim, value", [("exp", "abc"), ("exp", True), ("nbf", "0"), ("nbf", None)]
)
def test_create_refuses_invalid_numeric_dates(jwt, claims, claim, value):
    with pytest.raises(CreateTokenError, match=claim):
        jwt.create({**claims, claim: value})


def test_create_float_exp_in_claims(jwk, claims):
    jwt = WrapJWT(jwk, issuer=claims["iss"], audience=claims["aud"])
    exp = time.time() + 60.5

    assert jwt.verify(jwt.create({**claims, "exp": exp})).claims["exp"] == exp


def test_float_exp_with_max_token_lifetime(jwk, claims):
    jwt = WrapJWT(jwk, max_token_lifetime=60)

    with pytest.raises(CreateTokenError, match="max_token_lifetime"):
        jwt.create({**claims, "exp": time.time() + 60.5})


# 7 empty Vault mount


def test_vault_empty_mount():
    with patch("hvac.Client") as client:
        client.return_value.secrets.kv.v2.list_secrets.side_effect = (
            InvalidPath()
        )
        storage = StorageVault("url", "token", "mount")

    assert storage.list_kids() == []
    assert WrapJWK(storage).jwks() == {"keys": []}


# 8 max_age with a non-integer iat


def test_max_age_with_float_iat(jwk, claims):
    kid = last_kid(jwk)
    private = ECKey.import_key(key_part(jwk, "private"))
    jwt = WrapJWT(jwk, issuer=claims["iss"], audience=claims["aud"], max_age=60)

    def token(iat: float) -> str:
        payload = {**claims, "iat": iat, "exp": int(time.time()) + 60}
        return joserfc_jwt.encode(
            {"alg": "ES256", "kid": kid}, payload, private
        )

    # joserfc compares iat with the current second, not in the same second
    assert jwt.verify(token(time.time() - 2.5))
    with pytest.raises(TokenExpiredError):
        jwt.verify(token(time.time() - 120.5))


# second audit: CLI strings, durations


@pytest.mark.parametrize(
    "argv, expected",
    [
        (["token", "--sub=1.10"], ["token", '--sub="1.10"']),
        (["token", "--sub", "1e3"], ["token", "--sub", '"1e3"']),
        (["revoke", "--kid=123"], ["revoke", '--kid="123"']),
        (["token", "--token-type=at+jwt"], ["token", '--token-type="at+jwt"']),
        (["token", "--custom={a:1}"], ["token", "--custom={a:1}"]),
        (["token", "--exp=minutes=5"], ["token", "--exp=minutes=5"]),
        (["token", "--sub"], ["token", "--sub"]),
    ],
)
def test_keep_strings(argv, expected):
    assert keep_strings(argv) == expected


@pytest.mark.parametrize("sub", ["1.10", "1e3", "1_000", "007", "True"])
def test_cli_sub_is_kept(tmp_path, monkeypatch, capsys, sub):
    monkeypatch.setenv("CERT_DIR", str(tmp_path))
    GenerateJWT(storage="file").keys()
    capsys.readouterr()
    argv = ["genjw", "--storage=file", "token", "--iss=i", "--aud=a"]
    monkeypatch.setattr("sys.argv", [*argv, f"--sub={sub}", "--exp=minutes=5"])

    run()

    token = capsys.readouterr().out.strip()
    assert (
        WrapJWT(WrapJWK(StorageFile(str(tmp_path)))).decode(token).claims["sub"]
        == sub
    )


@pytest.mark.parametrize("value", [5, "5", "minutes=²"])
def test_duration_without_unit(value, capsys):
    with pytest.raises(SystemExit):
        parse_duration("--exp", value)
    assert "--exp=" in capsys.readouterr().err


# second audit: JWKS download does not block known keys


def test_jwks_download_does_not_block_known_keys(jwk):
    token = WrapJWT(jwk, issuer="i", audience="a").create({"sub": "1"}, exp=60)
    document = jwk.jwks()
    started, release = threading.Event(), threading.Event()
    session = MagicMock()

    def get(url, timeout):
        if session.get.call_count > 1:
            started.set()
            release.wait(5)
        response = MagicMock()
        response.json.return_value = document
        response.url = url
        return response

    session.get.side_effect = get
    storage = StorageJWKS(URL_JWKS, session=session, refresh_interval=0)
    verifier = WrapJWT(WrapJWK(storage), issuer="i", audience="a")
    verifier.verify(token)
    unknown = threading.Thread(
        target=lambda: pytest.raises(
            Exception, WrapJWK(storage).load_verification_key, "B" * 43
        )
    )
    unknown.start()
    assert started.wait(5)

    begin = time.monotonic()
    assert verifier.verify(token)
    assert time.monotonic() - begin < 1, "a known key does not wait"
    release.set()
    unknown.join()


# second audit: concurrent creation of the first keys


def test_concurrent_first_keys(storage):
    barrier = threading.Barrier(2)
    original = storage.get_last_kid

    def slow() -> str:
        try:
            return original()
        finally:
            barrier.wait(5)

    with patch.object(storage, "get_last_kid", side_effect=slow):
        threads = [
            threading.Thread(target=WrapJWK(storage).rotate) for _ in range(2)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    keys = WrapJWK(storage).list_keys()
    assert len(keys) == 2
    orphan = [k for k in keys if not k["last"]][0]["kid"]
    last = storage.get_last_kid()
    # rotate retires the losing keys when it sees the race, otherwise the
    # next prune retires them; they are deleted after max_token_lifetime
    WrapJWK(storage).prune(max_token_lifetime=3600)
    with patch("time.time", return_value=time.time() + 3602):
        WrapJWK(storage).prune(max_token_lifetime=3600)
    assert storage.list_kids() == [last]
    assert orphan != last


def test_rotate_sees_concurrent_first_keys(storage):
    """Another process saved its first keys after ours"""
    other = generate_keys()
    original = storage.save_keys

    def concurrent(kid: str, keys: dict) -> None:
        original(kid, keys)
        original(*other)

    with patch.object(storage, "save_keys", side_effect=concurrent):
        assert WrapJWK(storage).rotate() == other[0]

    ours = [k for k in WrapJWK(storage).list_keys() if not k["last"]][0]
    assert ours["retired"] is not None
