import ast
import time
import uuid
from typing import Any
from unittest.mock import patch

import fakeredis
import pytest

from joserfc_wrapper import StorageFile, StorageRedis, WrapJWK, WrapJWT
from joserfc_wrapper.cli.GenJWT import GenerateJWT


@pytest.fixture
def cli(tmp_path, monkeypatch) -> GenerateJWT:
    """CLI with file storage and generated keys"""
    monkeypatch.setenv("CERT_DIR", str(tmp_path))
    gen = GenerateJWT(storage="file")
    gen.keys()
    return gen


@pytest.mark.parametrize(
    "storage, env",
    [
        ("vault", ["VAULT_ADDR", "VAULT_TOKEN", "VAULT_MOUNT"]),
        ("file", ["CERT_DIR"]),
        ("redis", ["REDIS_URL"]),
    ],
)
def test_missing_env(monkeypatch, capsys, storage, env):
    for var in env:
        monkeypatch.delenv(var, raising=False)

    assert_fails(capsys, "Missing var", GenerateJWT, storage=storage)


def test_unknown_storage(capsys):
    assert_fails(capsys, "Allowed value is", GenerateJWT, storage="db")


def test_missing_cert_dir(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CERT_DIR", str(tmp_path / "missing"))

    assert_fails(capsys, "not exist", GenerateJWT, storage="file")


def test_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_DIR", str(tmp_path))

    result = GenerateJWT(storage="file").keys()

    assert result.startswith("New keys has been saved in 'file' storage")
    assert (tmp_path / "last-key-id.json").exists()


def test_token_check_show(cli, capsys):
    token = cli.token(iss="iss", aud="aud", uid=1, exp="minutes=5")

    assert cli.check(iss="iss", aud="aud", token=token) == "Token is valid."
    assert cli.show(token=token, header=True) == ""
    out = capsys.readouterr().out
    assert "'alg': 'ES256'" in out
    assert "'uid': 1" in out
    assert "'exp':" in out


def test_token_exp_seconds(cli, capsys):
    token = cli.token(iss="iss", aud="aud", uid=1, exp="hours=2")
    cli.show(token=token)

    claims = ast.literal_eval(capsys.readouterr().out.removeprefix("Claims: "))
    assert claims["exp"] - claims["iat"] == 7200


def test_token_exp_twice(cli, capsys):
    assert_fails(
        capsys,
        "not both",
        cli.token,
        iss="iss",
        aud="aud",
        uid=1,
        exp="minutes=5",
        custom={"exp": 1},
    )


def test_token_custom_claims(cli, capsys):
    token = cli.token(
        iss="iss",
        aud="aud",
        uid=1,
        exp="minutes=5",
        custom={"role": "admin", "uid": 2},
    )
    cli.show(token=token)

    out = capsys.readouterr().out
    assert "'role': 'admin'" in out
    # custom claims do not override required claims
    assert "'uid': 1" in out


def test_token_payload_rotates_keys(cli):
    kids = set()
    for _ in range(3):
        token = cli.token(
            iss="iss", aud="aud", uid=1, exp="minutes=5", payload=2
        )
        kids.add(token.split(".")[0])

    assert len(kids) == 2


def assert_fails(capsys, error: str, func, *args, **kwargs) -> None:
    """CLI command must exit with code 1 and print error to stderr"""
    with pytest.raises(SystemExit) as exc:
        func(*args, **kwargs)
    assert exc.value.code == 1
    assert error in capsys.readouterr().err


@pytest.mark.parametrize(
    "exp, error",
    [
        ("5", "bad format"),
        ("years=1", "not in valid units"),
        ("minutes=0", "must be an integer greater zero"),
        ("minutes=-5", "must be an integer greater zero"),
        ("minutes=x", "must be an integer greater zero"),
    ],
)
def test_token_bad_exp(cli, capsys, exp, error):
    assert_fails(capsys, error, cli.token, iss="iss", aud="aud", uid=1, exp=exp)


def test_token_bad_custom(cli, capsys):
    custom: Any = "x"
    assert_fails(
        capsys,
        "--custom must be a 'dict'",
        cli.token,
        iss="iss",
        aud="aud",
        uid=1,
        exp="minutes=5",
        custom=custom,
    )


@pytest.mark.parametrize(
    "payload, error",
    [(-1, "zero (unlimited) or greater"), ("5", "must be a 'int'")],
)
def test_token_bad_payload(cli, capsys, payload, error):
    assert_fails(
        capsys,
        error,
        cli.token,
        iss="iss",
        aud="aud",
        uid=1,
        exp="minutes=5",
        payload=payload,
    )


def test_token_bad_claims(cli, capsys):
    uid: Any = "1"
    assert_fails(
        capsys,
        "CreateTokenException",
        cli.token,
        iss="iss",
        aud="aud",
        uid=uid,
        exp="minutes=5",
    )


def test_token_requires_exp(cli, capsys):
    assert_fails(
        capsys, "--exp is required", cli.token, iss="iss", aud="aud", uid=1
    )


def test_check_shows_reason(cli, capsys):
    token = cli.token(iss="iss", aud="aud", uid=1, exp="minutes=5")

    assert_fails(
        capsys,
        "Token is invalid. TokenClaimError",
        cli.check,
        iss="iss",
        aud="other",
        token=token,
    )


def test_check_token_without_exp(cli, capsys, tmp_path):
    """Tokens without exp (created by the library) are invalid"""
    jwt = WrapJWT(WrapJWK(StorageFile(str(tmp_path))))
    token = jwt.create({"iss": "iss", "aud": "aud", "uid": 1})

    assert_fails(
        capsys,
        "Missing claim: 'exp'",
        cli.check,
        iss="iss",
        aud="aud",
        token=token,
    )


def test_check_invalid_claims(cli, capsys):
    token = cli.token(iss="iss", aud="aud", uid=1, exp="minutes=5")

    assert_fails(
        capsys,
        "Token is invalid.",
        cli.check,
        iss="other",
        aud="aud",
        token=token,
    )


def test_check_malformed_token(cli, capsys):
    assert_fails(
        capsys, "TokenDecodeError", cli.check, iss="iss", aud="aud", token="x"
    )


def test_show_malformed_token(cli, capsys):
    assert_fails(capsys, "TokenDecodeError", cli.show, token="x")


def test_keys_error(cli, capsys, monkeypatch):
    def broken(*args, **kwargs):
        raise OSError("disk full")

    # keys rotates the existing keys of the cli fixture
    monkeypatch.setattr(StorageFile, "replace_last_keys", broken)

    assert_fails(capsys, "OSError: disk full", cli.keys)


@pytest.mark.parametrize("version, expected", [(None, 2), ("1", 1), ("2", 2)])
def test_vault_kv_version(monkeypatch, version, expected):
    for var in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_MOUNT"):
        monkeypatch.setenv(var, "x")
    if version is None:
        monkeypatch.delenv("VAULT_KV_VERSION", raising=False)
    else:
        monkeypatch.setenv("VAULT_KV_VERSION", version)

    with patch(
        "joserfc_wrapper.cli.GenJWT.StorageVault", autospec=True
    ) as vault:
        GenerateJWT(storage="vault")

    assert vault.call_args.kwargs["kv_version"] == expected


def test_vault_bad_kv_version(monkeypatch, capsys):
    for var in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_MOUNT"):
        monkeypatch.setenv(var, "x")
    monkeypatch.setenv("VAULT_KV_VERSION", "3")

    assert_fails(capsys, "VAULT_KV_VERSION", GenerateJWT, storage="vault")


def test_rotate_and_list(cli, capsys):
    token = cli.token(iss="iss", aud="aud", uid=1, exp="minutes=5")

    assert cli.rotate().startswith("New keys has been saved")
    lines = cli.list().splitlines()

    assert len(lines) == 2
    assert "retired" in lines[0] and "tokens: 1" in lines[0]
    assert "last" in lines[1] and "retired: -" in lines[1]
    # tokens signed by the retired keys stay valid
    assert cli.check(iss="iss", aud="aud", token=token) == "Token is valid."


def test_revoke_requires_yes(cli, capsys):
    kid = cli.list().split()[0]

    assert_fails(capsys, "Add --yes to revoke", cli.revoke, kid=kid)
    listed = cli.list()
    assert "revoked: -" in listed and " revoked " not in listed


def test_revoke(cli, capsys):
    token = cli.token(iss="iss", aud="aud", uid=1, exp="minutes=5")
    kid = cli.list().split()[0]

    result = cli.revoke(kid=kid, yes=True)

    assert (
        result == f"Key {kid} has been revoked. New keys have been generated."
    )
    assert_fails(
        capsys,
        "TokenKeyRevokedError",
        cli.check,
        iss="iss",
        aud="aud",
        token=token,
    )


def test_revoke_unknown_kid(cli, capsys):
    assert_fails(
        capsys, "KeysNotFoundError", cli.revoke, kid=uuid.uuid4().hex, yes=True
    )


def test_prune(cli):
    old = cli.list().split()[0]
    cli.rotate()

    assert cli.prune(lifetime="hours=1") == "No keys to delete."
    with patch("time.time", return_value=time.time() + 3602):
        assert cli.prune(lifetime="hours=1") == f"Deleted keys: {old}"
    assert old not in cli.list()


def test_prune_bad_lifetime(cli, capsys):
    assert_fails(
        capsys, "must be an integer greater zero", cli.prune, lifetime="hours=0"
    )


def test_token_max_key_age(cli):
    first = cli.list().split()[0]

    cli.token(
        iss="iss", aud="aud", uid=1, exp="minutes=5", max_key_age="days=1"
    )
    assert cli.list().split()[0] == first
    with patch("time.time", return_value=time.time() + 86401):
        cli.token(
            iss="iss", aud="aud", uid=1, exp="minutes=5", max_key_age="days=1"
        )
    assert len(cli.list().splitlines()) == 2


def test_token_payload_is_deprecated(cli, capsys):
    cli.token(iss="iss", aud="aud", uid=1, exp="minutes=5", payload=5)

    assert "--payload is deprecated" in capsys.readouterr().err


def test_vault_kv_v1_is_deprecated(monkeypatch, capsys):
    for var in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_MOUNT"):
        monkeypatch.setenv(var, "x")
    monkeypatch.setenv("VAULT_KV_VERSION", "1")

    with patch("joserfc_wrapper.cli.GenJWT.StorageVault", autospec=True):
        GenerateJWT(storage="vault")

    assert "KV v1 (VAULT_KV_VERSION=1) is deprecated" in capsys.readouterr().err


def test_revoke_token(cli, capsys):
    token = cli.token(iss="iss", aud="aud", uid=1, exp="minutes=5")
    other = cli.token(iss="iss", aud="aud", uid=2, exp="minutes=5")

    assert cli.revoke_token(token=token) == "Token has been revoked."
    assert_fails(
        capsys,
        "TokenRevokedError",
        cli.check,
        iss="iss",
        aud="aud",
        token=token,
    )
    assert cli.check(iss="iss", aud="aud", token=other) == "Token is valid."


def test_revoke_token_malformed(cli, capsys):
    assert_fails(capsys, "TokenDecodeError", cli.revoke_token, token="x")


@pytest.fixture
def fake_redis(monkeypatch):
    """StorageRedis.from_url returns a storage with fakeredis"""
    client = fakeredis.FakeRedis()
    calls = []

    def from_url(url: str, prefix: str = "jwt:", **options):
        calls.append((url, prefix))
        return StorageRedis(client, prefix=prefix)

    monkeypatch.setattr(StorageRedis, "from_url", staticmethod(from_url))
    return calls


def test_redis_storage(monkeypatch, fake_redis):
    monkeypatch.setenv("REDIS_URL", "redis://host:6379/1")
    monkeypatch.setenv("REDIS_PREFIX", "app:")

    cli = GenerateJWT(storage="redis")
    cli.keys()
    token = cli.token(iss="iss", aud="aud", uid=1, exp="minutes=5")
    cli.revoke_token(token=token)

    assert fake_redis == [("redis://host:6379/1", "app:")]
    assert len(cli.list().splitlines()) == 1


def test_redis_default_prefix(monkeypatch, fake_redis):
    monkeypatch.setenv("REDIS_URL", "redis://host")
    monkeypatch.delenv("REDIS_PREFIX", raising=False)

    GenerateJWT(storage="redis")

    assert fake_redis == [("redis://host", "jwt:")]
