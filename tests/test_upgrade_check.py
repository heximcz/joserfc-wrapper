"""genjw upgrade-check (0.9.1)"""

import json
import time
from unittest.mock import patch

import pytest

from joserfc_wrapper import WrapJWK, WrapJWT
from joserfc_wrapper.cli.gen_jwt import GenerateJWT
from joserfc_wrapper.cli.upgrade_check import (
    BLOCKER,
    WARNING,
    check_keys,
    check_python,
    check_token,
    check_vault,
    report,
    split_tokens,
)

from .test_jwk import LegacyStorage


def levels(findings) -> list[str]:
    return [f.level for f in findings]


@pytest.fixture
def cli(tmp_path, monkeypatch) -> GenerateJWT:
    monkeypatch.setenv("CERT_DIR", str(tmp_path))
    gen = GenerateJWT(storage="file")
    gen.keys()
    return gen


@pytest.fixture
def issuer(jwk) -> WrapJWT:
    return WrapJWT(jwk, issuer="iss", audience="aud")


def test_python():
    assert levels(check_python((3, 10))) == [BLOCKER]
    assert not check_python((3, 11))
    assert not check_python((3, 14))


def test_vault():
    assert levels(check_vault(2)) == [WARNING]
    assert "[vault]" in check_vault(2)[0].advice
    findings = check_vault(1)
    assert levels(findings) == [BLOCKER, WARNING]
    assert "KV v1" in findings[0].message


def test_keys_ok(jwk):
    jwk.rotate()

    assert not check_keys(jwk, None)


def test_keys_without_metadata(storage, jwk, tmp_path):
    """Keys of versions older than 0.5.0"""
    old = jwk.get_kid()
    path = tmp_path / f"{old}.json"
    record = json.loads(path.read_text())
    del record["data"]["created"]
    path.write_text(json.dumps(record))
    jwk.generate_keys()
    jwk.save_keys()

    findings = check_keys(WrapJWK(storage), None)

    assert levels(findings) == [WARNING]
    assert old in findings[0].message


def test_last_key_without_created(storage, jwk, tmp_path):
    path = tmp_path / f"{jwk.get_kid()}.json"
    record = json.loads(path.read_text())
    del record["data"]["created"]
    path.write_text(json.dumps(record))

    findings = check_keys(WrapJWK(storage), None)

    assert levels(findings) == [WARNING]
    assert "Rotate" in findings[0].advice


def test_keys_for_prune(jwk):
    old = jwk.get_kid()
    jwk.rotate()

    assert not check_keys(jwk, 3600)
    with patch("time.time", return_value=time.time() + 3602):
        findings = check_keys(jwk, 3600)
    assert levels(findings) == [WARNING]
    assert old in findings[0].message


def test_keys_cannot_be_listed():
    jwk = WrapJWK(LegacyStorage())
    jwk.generate_keys()
    jwk.save_keys()

    findings = check_keys(jwk, None)

    assert levels(findings) == [WARNING]
    assert "cannot be listed" in findings[0].message


def test_token_ok(issuer):
    assert not check_token(issuer, issuer.create({"sub": "1"}, exp=60))


def test_token_without_sub(issuer):
    with pytest.warns(DeprecationWarning):
        token = issuer.create({"uid": 1}, exp=60)

    findings = check_token(issuer, token)

    assert levels(findings) == [BLOCKER, WARNING]
    assert "'sub'" in findings[0].message and "'uid'" in findings[1].message


def test_token_without_jti(issuer):
    with patch("uuid.uuid4") as uuid4:
        uuid4.return_value.hex = ""
        token = issuer.create({"sub": "1"}, exp=60)
    assert not issuer.decode(token).claims["jti"]

    findings = check_token(issuer, token)

    assert levels(findings) == [WARNING]
    assert "'jti'" in findings[0].message


def test_token_expired(issuer):
    token = issuer.create({"sub": "1"}, exp=60)

    with patch("time.time", return_value=time.time() + 120):
        findings = check_token(issuer, token)

    assert levels(findings) == [WARNING]
    assert "expired" in findings[0].message


def test_token_invalid(issuer):
    findings = check_token(issuer, "x.y.z")

    assert levels(findings) == [WARNING]
    assert "cannot be decoded" in findings[0].message


@pytest.mark.parametrize(
    "value, expected",
    [
        (None, []),
        ("", []),
        ("a.b.c", ["a.b.c"]),
        ("a.b.c, d.e.f", ["a.b.c", "d.e.f"]),
        (("a.b.c", "d.e.f"), ["a.b.c", "d.e.f"]),
    ],
)
def test_split_tokens(value, expected):
    assert split_tokens(value) == expected


def test_report():
    findings = check_vault(1)

    text = report("vault", findings)

    assert "Result: 1 blocker(s), 1 warning(s)." in text
    assert "Fix the blockers" in text
    assert "preparing-for-1-0-0" in text
    assert all(len(line) <= 79 for line in text.splitlines()[:-1])
    assert "Ready for 1.0.0." in report("file", [])


def test_cli_ready(cli, capsys):
    token = cli.token(iss="iss", aud="aud", sub="1", exp="minutes=5")

    with patch("sys.version_info", (3, 11, 0)):
        result = cli.upgrade_check(token=token)

    assert "Result: 0 blocker(s), 0 warning(s)." in result


def test_cli_blocker_exits_1(cli, capsys):
    token = cli.token(iss="iss", aud="aud", uid=1, exp="minutes=5")

    with pytest.raises(SystemExit) as exc:
        cli.upgrade_check(token=token)

    assert exc.value.code == 1
    assert "BLOCKER" in capsys.readouterr().out


def test_cli_lifetime(cli):
    cli.rotate()

    with patch("sys.version_info", (3, 11, 0)):
        assert "0 warning(s)" in cli.upgrade_check(lifetime="hours=1")
        with patch("time.time", return_value=time.time() + 3602):
            assert "1 warning(s)" in cli.upgrade_check(lifetime="hours=1")


def test_cli_vault_kv_v1(monkeypatch, capsys):
    for var in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_MOUNT"):
        monkeypatch.setenv(var, "x")
    monkeypatch.setenv("VAULT_KV_VERSION", "1")

    with patch("joserfc_wrapper.cli.gen_jwt.StorageVault", autospec=True):
        cli = GenerateJWT(storage="vault")
        with pytest.raises(SystemExit):
            cli.upgrade_check()

    assert "Vault KV v1" in capsys.readouterr().out
