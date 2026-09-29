"""
Checks before the upgrade to 1.0.0 ('genjw upgrade-check')

Only for the command line of the 0.9.x series, not a public API, it will
be removed in 1.0.0.
"""

import importlib.metadata
import sys
import textwrap
import time
import warnings
from dataclasses import dataclass

from joserfc_wrapper.exceptions import WrapperErrors
from joserfc_wrapper.wrap_jwk import WrapJWK
from joserfc_wrapper.wrap_jwt import WrapJWT

GUIDE = (
    "https://joserfc-wrapper.readthedocs.io/en/stable/upgrading.html"
    "#preparing-for-1-0-0"
)

SEPARATOR = ", "
EMPTY = ""

BLOCKER = "BLOCKER"
WARNING = "WARNING"


@dataclass
class Finding:
    """One result of the check"""

    level: str
    message: str
    advice: str


def check_python(version: tuple[int, int]) -> list[Finding]:
    """1.0.0 needs Python 3.11 or newer"""
    if version >= (3, 11):
        return []
    return [
        Finding(
            BLOCKER,
            f"Python {version[0]}.{version[1]} is not supported by 1.0.0.",
            "Upgrade to Python 3.11 or newer.",
        )
    ]


def check_vault(kv_version: int) -> list[Finding]:
    """KV v1 is removed in 1.0.0, hvac is only in the 'vault' extra"""
    findings = [
        Finding(
            WARNING,
            "1.0.0 installs the Vault client (hvac) only with the 'vault' "
            "extra.",
            'Install "joserfc-wrapper[vault]" (requirements, pyproject).',
        )
    ]
    if kv_version == 1:
        findings.insert(
            0,
            Finding(
                BLOCKER,
                "Vault KV v1 (VAULT_KV_VERSION=1) is not supported by 1.0.0.",
                "Copy the keys to a KV v2 mount, or create new keys there "
                "and keep the KV v1 mount until the old tokens expire.",
            ),
        )
    return findings


def check_keys(wrapjwk: WrapJWK, lifetime: int | None) -> list[Finding]:
    """
    Keys without metadata, keys which 'prune' would delete (only with the
    longest lifetime of tokens)
    """
    try:
        keys = wrapjwk.list_keys()
    except WrapperErrors as e:
        return [
            Finding(
                WARNING,
                f"The keys cannot be listed: {e}",
                "Vault needs the 'list' capability on <mount>/metadata/*, "
                "a custom storage 'list_kids'.",
            )
        ]
    findings = []
    legacy = [k["kid"] for k in keys if k["created"] is None and not k["last"]]
    if legacy:
        findings.append(
            Finding(
                WARNING,
                f"{len(legacy)} old key(s) without metadata (created by "
                f"versions older than 0.5.0): {SEPARATOR.join(legacy)}.",
                "They do not block 1.0.0, but 'prune' never deletes them. "
                "When all their tokens have expired, delete them in the "
                "storage manually (the file <kid>.json, the Vault secret "
                "<kid> or the Redis key <prefix><kid>), or keep them.",
            )
        )
    last = [k for k in keys if k["last"]]
    if last and last[0]["created"] is None:
        findings.append(
            Finding(
                WARNING,
                "The last key has no creation time (created by a version "
                "older than 0.5.0).",
                "Rotate the keys ('genjw rotate' or 'max_key_age').",
            )
        )
    if lifetime is not None:
        now = int(time.time())
        waiting = [
            k["kid"]
            for k in keys
            if not k["last"]
            and k["retired"] is not None
            and now > k["retired"] + lifetime
        ]
        if waiting:
            findings.append(
                Finding(
                    WARNING,
                    f"{len(waiting)} key(s) without valid tokens are not "
                    f"deleted: {SEPARATOR.join(waiting)}.",
                    "Run 'prune' regularly (e.g. 'genjw prune "
                    "--lifetime=...' from cron).",
                )
            )
    return findings


def check_token(wrapjwt: WrapJWT, token: str) -> list[Finding]:
    """Claims of a token created by the application"""
    short = token[:16] + "..."
    try:
        claims = wrapjwt.decode(token).claims
    except Exception as e:  # pylint: disable=broad-exception-caught
        return [
            Finding(
                WARNING,
                f"Token {short} cannot be decoded: {type(e).__name__}: {e}",
                "Check tokens signed by the keys of this storage.",
            )
        ]
    findings = []
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        findings.append(
            Finding(
                BLOCKER,
                f"Token {short} has no 'sub', 'verify' of 1.0.0 rejects it.",
                "Create tokens with 'sub' (a string, e.g. the user ID) and "
                "wait until the tokens without it expire.",
            )
        )
    if "uid" in claims:
        findings.append(
            Finding(
                WARNING,
                f"Token {short} has 'uid', a custom claim in 1.0.0.",
                "Move the application to 'sub'.",
            )
        )
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        findings.append(
            Finding(
                WARNING,
                f"Token {short} has no 'jti' (created by a version older "
                "than 0.4.0), it cannot be revoked.",
                "Create new tokens, they get 'jti' automatically.",
            )
        )
    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and exp < time.time():
        findings.append(
            Finding(
                WARNING,
                f"Token {short} has expired, it does not matter for the "
                "upgrade.",
                "Check a token which the application creates now.",
            )
        )
    return findings


def split_tokens(tokens: object) -> list[str]:
    """Tokens from --token: a string (more separated by commas) or a list"""
    if tokens is None or tokens == "":
        return []
    items = tokens if isinstance(tokens, (list, tuple)) else [tokens]
    result = []
    for item in items:
        result += [t.strip() for t in str(item).split(",") if t.strip()]
    return result


def versions() -> str:
    """Versions of Python and of the optional dependencies"""
    parts = [f"Python {sys.version_info[0]}.{sys.version_info[1]}"]
    for name in ("joserfc-wrapper", "joserfc", "hvac", "redis"):
        try:
            parts.append(f"{name} {importlib.metadata.version(name)}")
        except importlib.metadata.PackageNotFoundError:
            parts.append(f"{name} -")
    return ", ".join(parts)


def report(storage: str, findings: list[Finding]) -> str:
    """Text report of the findings"""
    lines = [
        f"Upgrade check for joserfc-wrapper 1.0.0, storage: {storage}",
        versions(),
        "",
    ]
    for finding in findings:
        for text, first in ((finding.message, True), (finding.advice, False)):
            lines += textwrap.wrap(
                text,
                width=79,
                initial_indent=f"{finding.level if first else EMPTY:8} ",
                subsequent_indent=" " * 9,
                break_long_words=False,
                break_on_hyphens=False,
            )
    blockers = sum(f.level == BLOCKER for f in findings)
    warns = len(findings) - blockers
    if findings:
        lines.append("")
    lines.append(f"Result: {blockers} blocker(s), {warns} warning(s).")
    if blockers:
        lines.append("Fix the blockers before the upgrade to 1.0.0.")
    elif warns:
        lines.append("Ready for 1.0.0, see the warnings.")
    else:
        lines.append("Ready for 1.0.0.")
    lines.append(f"Guide: {GUIDE}")
    return "\n".join(lines)


def run_checks(
    storage: str,
    wrapjwk: WrapJWK,
    kv_version: int | None,
    tokens: list[str],
    lifetime: int | None = None,
) -> list[Finding]:
    """All checks, the blockers first"""
    findings = check_python(sys.version_info[:2])
    if storage == "vault":
        findings += check_vault(kv_version or 2)
    findings += check_keys(wrapjwk, lifetime)
    wrapjwt = WrapJWT(wrapjwk)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        for token in tokens:
            findings += check_token(wrapjwt, token)
    return sorted(findings, key=lambda f: f.level != BLOCKER)
