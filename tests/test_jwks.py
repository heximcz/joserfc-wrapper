"""Cache of verification keys, JWKS and StorageJWKS (0.7.0)"""

import base64
import json
import os
import stat
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from joserfc_wrapper import (
    ConfigurationError,
    KeysLoadError,
    StorageFile,
    StorageJWKS,
    TokenKidUnknownError,
    TokenKeyRevokedError,
    WrapJWK,
    WrapJWT,
)
from joserfc_wrapper.cli.gen_jwt import GenerateJWT
from joserfc_wrapper.testing import check_read_only_storage

from .test_jwk import LegacyStorage

ISS, AUD = "https://example.com", "api"
URL = "https://auth.example.com/.well-known/jwks.json"


def jwt_for(jwk: WrapJWK, **config) -> WrapJWT:
    return WrapJWT(jwk, issuer=ISS, audience=AUD, **config)


def later(seconds: float):
    """Patch the monotonic clock of the caches"""
    return patch("time.monotonic", return_value=time.monotonic() + seconds)


@pytest.fixture
def issuer(tmp_path) -> WrapJWK:
    jwk = WrapJWK(StorageFile(str(tmp_path / "keys")))
    os.mkdir(tmp_path / "keys")
    jwk.rotate()
    return jwk


def session_for(*documents: Any) -> MagicMock:
    """requests.Session returning the documents (or raising exceptions)"""
    session = MagicMock()
    responses = []
    for document in documents:
        if isinstance(document, Exception):
            responses.append(document)
        else:
            response = MagicMock()
            response.json.return_value = document
            responses.append(response)
    session.get.side_effect = responses
    return session


# cache of verification keys


def test_verify_uses_cache(storage, jwk):
    token = jwt_for(jwk).create({"uid": 1}, exp=60)

    with patch.object(storage, "load_keys", wraps=storage.load_keys) as load:
        for _ in range(3):
            # a new WrapJWK and WrapJWT for each request, the same storage
            assert jwt_for(WrapJWK(storage)).verify(token)

    assert load.call_count == 1


def test_cache_disabled(tmp_path, jwk):
    storage = StorageFile(str(tmp_path), key_cache_ttl=0)
    token = jwt_for(jwk).create({"uid": 1}, exp=60)

    with patch.object(storage, "load_keys", wraps=storage.load_keys) as load:
        for _ in range(3):
            jwt_for(WrapJWK(storage)).verify(token)

    assert load.call_count == 3


def test_cache_expires(storage, jwk):
    token = jwt_for(jwk).create({"uid": 1}, exp=60)
    jwt_for(jwk).verify(token)

    with patch.object(storage, "load_keys", wraps=storage.load_keys) as load:
        with later(storage.key_cache_ttl + 1):
            jwt_for(jwk).verify(token)

    assert load.call_count == 1


def test_revoke_clears_cache_of_the_process(storage, jwk):
    token = jwt_for(jwk).create({"uid": 1}, exp=60)
    jwt_for(jwk).verify(token)

    WrapJWK(storage).revoke(jwk.get_kid())

    with pytest.raises(TokenKeyRevokedError):
        jwt_for(jwk).verify(token)


def test_revoke_by_other_process_after_ttl(tmp_path, jwk):
    """Another storage object (process) sees the revocation after TTL"""
    token = jwt_for(jwk).create({"uid": 1}, exp=60)
    verifier = WrapJWK(StorageFile(str(tmp_path), key_cache_ttl=60))
    jwt_for(verifier).verify(token)

    jwk.revoke(jwk.get_kid())

    assert jwt_for(verifier).verify(token)
    with later(61):
        with pytest.raises(TokenKeyRevokedError):
            jwt_for(verifier).verify(token)


def test_verify_does_not_load_private_keys(storage, jwk):
    """decode changes no loaded keys of WrapJWK"""
    first = jwk.get_kid()
    token = jwt_for(jwk).create({"uid": 1}, exp=60)
    jwk.rotate()
    last = jwk.get_kid()

    assert jwt_for(jwk).verify(token).header["kid"] == first
    assert jwk.get_kid() == last


@pytest.mark.parametrize("ttl", [-1, "300", True])
def test_invalid_cache_ttl(tmp_path, ttl):
    with pytest.raises(ValueError):
        StorageFile(str(tmp_path), key_cache_ttl=ttl)


def test_cache_threads(storage, jwk):
    tokens = [jwt_for(jwk).create({"uid": i}, exp=60) for i in range(20)]

    def verify(token: str) -> int:
        return jwt_for(WrapJWK(storage)).verify(token).claims["uid"]

    with ThreadPoolExecutor(8) as pool:
        assert sorted(pool.map(verify, tokens * 5)) == sorted(
            list(range(20)) * 5
        )


# WrapJWK.jwks


def test_jwks(storage, jwk):
    first = jwk.get_kid()
    jwk.rotate()
    second = jwk.get_kid()
    jwk.rotate()
    jwk.revoke(second)

    keys = {key["kid"]: key for key in jwk.jwks()["keys"]}

    assert first in keys and jwk.get_kid() in keys
    assert second not in keys, "revoked keys are not published"
    for key in keys.values():
        assert set(key) == {"kid", "kty", "crv", "x", "y", "use", "alg"}
        assert key["alg"] == "ES256" and key["use"] == "sig"
    assert json.dumps(jwk.jwks())


def test_jwks_new_keys_immediately(storage, jwk):
    """A rotation by another process is in the JWKS without waiting"""
    jwk.jwks()
    other = WrapJWK(StorageFile(storage_dir(storage)))
    other.rotate()

    assert other.get_kid() in {key["kid"] for key in jwk.jwks()["keys"]}


def storage_dir(storage: StorageFile) -> str:
    return storage._StorageFile__cert_dir  # type: ignore[attr-defined]


def test_jwks_storage_without_listing():
    jwk = WrapJWK(LegacyStorage())
    jwk.generate_keys()
    jwk.save_keys()

    with pytest.raises(KeysLoadError, match="does not support listing"):
        jwk.jwks()


# StorageJWKS


def test_storage_jwks_from_file(issuer, tmp_path):
    token = jwt_for(issuer).create({"uid": 1}, exp=60)
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps(issuer.jwks()))

    for source in (str(path), f"file://{path}"):
        verifier = WrapJWK(StorageJWKS(source))
        assert jwt_for(verifier).verify(token).claims["uid"] == 1


def test_storage_jwks_from_url(issuer):
    token = jwt_for(issuer).create({"uid": 1}, exp=60)
    session = session_for(issuer.jwks())
    storage = StorageJWKS(URL, session=session, timeout=3)

    assert jwt_for(WrapJWK(storage)).verify(token)
    assert jwt_for(WrapJWK(storage)).verify(token)

    session.get.assert_called_once_with(URL, timeout=3)


def test_storage_jwks_contract(issuer):
    storage = StorageJWKS(URL, session=session_for(issuer.jwks()))

    check_read_only_storage(storage, issuer.get_kid())


def test_storage_jwks_unknown_kid_refresh(issuer):
    old = issuer.jwks()
    issuer.rotate()
    token = jwt_for(issuer).create({"uid": 1}, exp=60)
    session = session_for(old, issuer.jwks())
    storage = StorageJWKS(URL, session=session, refresh_interval=60)
    storage.load_jwks()

    # the new key is not in the old JWKS, downloaded again at once
    with later(61):
        assert jwt_for(WrapJWK(storage)).verify(token)
    assert session.get.call_count == 2


def test_storage_jwks_unknown_kid_rate_limit(issuer):
    session = session_for(issuer.jwks(), issuer.jwks())
    storage = StorageJWKS(URL, session=session, refresh_interval=60)
    token = forged_token(uuid.uuid4().hex)
    jwk = WrapJWK(storage)

    for _ in range(5):
        with pytest.raises(TokenKidUnknownError):
            jwt_for(jwk).verify(token)

    assert session.get.call_count == 1


def forged_token(kid: str) -> str:
    """A token with a kid which is not in the JWKS"""
    header = json.dumps({"alg": "ES256", "kid": kid}).encode()
    b64 = base64.urlsafe_b64encode(header).rstrip(b"=").decode()
    return f"{b64}.e30.c2ln"


def test_storage_jwks_ttl_refresh(issuer):
    first = issuer.jwks()
    session = session_for(first, first)
    storage = StorageJWKS(URL, session=session, ttl=300)
    token = jwt_for(issuer).create({"uid": 1}, exp=60)
    jwt_for(WrapJWK(storage)).verify(token)

    with later(301):
        jwt_for(WrapJWK(storage)).verify(token)

    assert session.get.call_count == 2


def test_storage_jwks_revoked_key(issuer):
    """A revoked key disappears from the JWKS after the next download"""
    token = jwt_for(issuer).create({"uid": 1}, exp=60)
    before = issuer.jwks()
    issuer.revoke(issuer.get_kid())
    session = session_for(before, issuer.jwks())
    storage = StorageJWKS(URL, session=session, ttl=300)
    assert jwt_for(WrapJWK(storage)).verify(token)

    with later(301):
        with pytest.raises(TokenKidUnknownError):
            jwt_for(WrapJWK(storage)).verify(token)


def test_storage_jwks_source_down_uses_stale(issuer):
    token = jwt_for(issuer).create({"uid": 1}, exp=60)
    down = OSError("connection refused")
    session = session_for(issuer.jwks(), down, down)
    storage = StorageJWKS(URL, session=session, ttl=300, max_stale=3600)
    jwt_for(WrapJWK(storage)).verify(token)

    # older JWKS is used while the source is down
    with later(400):
        assert jwt_for(WrapJWK(storage)).verify(token)
    # too old
    with later(3700):
        with pytest.raises(KeysLoadError, match="max_stale"):
            jwt_for(WrapJWK(storage)).verify(token)


def test_storage_jwks_first_download_fails(issuer):
    token = jwt_for(issuer).create({"uid": 1}, exp=60)
    session = session_for(OSError("down"), issuer.jwks())
    storage = StorageJWKS(URL, session=session)

    with pytest.raises(KeysLoadError, match="not loaded"):
        jwt_for(WrapJWK(storage)).verify(token)
    # retried after a second, not after refresh_interval
    with later(2):
        assert jwt_for(WrapJWK(storage)).verify(token)


def test_storage_jwks_http_status_error(issuer):
    response = MagicMock()
    response.raise_for_status.side_effect = OSError("503 Server Error")
    session = MagicMock()
    session.get.return_value = response
    token = jwt_for(issuer).create({"uid": 1}, exp=60)

    with pytest.raises(KeysLoadError, match="503"):
        jwt_for(WrapJWK(StorageJWKS(URL, session=session))).verify(token)


@pytest.mark.parametrize(
    "document, error",
    [
        ({"x": 1}, "Invalid JWKS"),
        ([], "Invalid JWKS"),
        ({"keys": ["x"]}, "not an object"),
        (
            {"keys": [{"kty": "EC", "crv": "P-256", "kid": "../x"}]},
            "Invalid Key ID",
        ),
    ],
)
def test_storage_jwks_invalid_document(issuer, document, error):
    token = jwt_for(issuer).create({"uid": 1}, exp=60)
    storage = StorageJWKS(URL, session=session_for(document))

    with pytest.raises(KeysLoadError, match=error):
        jwt_for(WrapJWK(storage)).verify(token)


def test_storage_jwks_refuses_private_key(issuer):
    key = {**issuer.get_private_key(), "kid": issuer.get_kid()}
    token = jwt_for(issuer).create({"uid": 1}, exp=60)
    storage = StorageJWKS(URL, session=session_for({"keys": [key]}))

    with pytest.raises(KeysLoadError, match="private key"):
        jwt_for(WrapJWK(storage)).verify(token)


def test_storage_jwks_ignores_other_keys(issuer):
    other = [
        {"kty": "RSA", "kid": "rsa1", "n": "x", "e": "AQAB"},
        {"kty": "oct", "k": "x"},
        {**issuer.jwks()["keys"][0], "use": "enc"},
    ]
    storage = StorageJWKS(URL, session=session_for({"keys": other}))

    assert storage.load_jwks() == {"keys": []}


@pytest.mark.parametrize(
    "source, options",
    [
        ("http://auth.example.com/jwks.json", {}),
        ("ftp://auth.example.com/jwks.json", {}),
        ("", {}),
        (URL, {"ttl": -1}),
        (URL, {"refresh_interval": "60"}),
        (URL, {"max_stale": 10, "ttl": 300}),
        (URL, {"timeout": True}),
    ],
)
def test_storage_jwks_invalid_parameters(source, options):
    with pytest.raises(ValueError):
        StorageJWKS(source, **options)


def test_storage_jwks_allow_http(issuer):
    storage = StorageJWKS(
        "http://127.0.0.1/jwks.json",
        allow_http=True,
        session=session_for(issuer.jwks()),
    )

    assert storage.load_jwks()["keys"]


def test_storage_jwks_is_read_only(issuer):
    storage = StorageJWKS(URL, session=session_for(issuer.jwks()))
    jwk = WrapJWK(storage)

    with pytest.raises(KeysLoadError, match="only verify tokens"):
        jwt_for(jwk).create({"uid": 1}, exp=60)
    with pytest.raises(KeysLoadError, match="only verify tokens"):
        jwk.rotate()
    with pytest.raises(ConfigurationError, match="does not support"):
        jwt_for(jwk, revocation=True)


def test_storage_jwks_republish(issuer):
    """load_jwks of StorageJWKS returns the downloaded JWKS"""
    storage = StorageJWKS(URL, session=session_for(issuer.jwks()))

    assert WrapJWK(storage).jwks() == issuer.jwks()


# CLI


def test_cli_jwks(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CERT_DIR", str(tmp_path))
    cli = GenerateJWT(storage="file")
    cli.keys()

    printed = json.loads(cli.jwks())
    assert len(printed["keys"]) == 1

    output = tmp_path / "public" / "jwks.json"
    output.parent.mkdir()
    assert cli.jwks(output=str(output)) == f"JWKS has been saved to '{output}'."
    assert json.loads(output.read_text()) == printed
    assert stat.S_IMODE(output.stat().st_mode) == 0o644
    assert [p.name for p in output.parent.iterdir()] == ["jwks.json"]


def test_cli_jwks_bad_output(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CERT_DIR", str(tmp_path))
    cli = GenerateJWT(storage="file")
    cli.keys()

    with pytest.raises(SystemExit):
        cli.jwks(output=str(tmp_path / "missing" / "jwks.json"))
    assert "FileNotFoundError" in capsys.readouterr().err
