"""compact token header helpers"""

import base64
import hashlib
import binascii
import json
import re
import uuid
from joserfc_wrapper.exceptions import TokenDecodeError, TokenKidInvalidError


def read_header(token: str) -> dict:
    """
    Decode protected header of a compact JWS/JWE token without verification

    :param token: compact token
    :returns: header
    :raises TokenDecodeError:
    """
    try:
        header = token.split(".")[0]
        header += "=" * (-len(header) % 4)
        result = json.loads(base64.urlsafe_b64decode(header).decode("utf-8"))
    except (
        AttributeError,
        binascii.Error,
        UnicodeDecodeError,
        ValueError,
    ) as e:
        raise TokenDecodeError from e
    if not isinstance(result, dict):
        raise TokenDecodeError
    return result


def read_kid(token: str, required: bool = True) -> str:
    """
    Return valid Key ID from a token header

    :param token: compact token
    :param required: raise if the header has no kid, otherwise return ""
    :returns: Key ID
    :raises TokenDecodeError, TokenKidInvalidError:
    """
    kid = read_header(token).get("kid")
    if kid is None and not required:
        return ""
    if not isinstance(kid, str) or not is_valid_kid(kid):
        raise TokenKidInvalidError
    return kid


def jti_digest(jti: str) -> str:
    """
    Storage name of a token ID: SHA-256 hex digest

    A custom 'jti' is any string, the digest is safe as a file name, Vault
    path or Redis key.
    """
    return hashlib.sha256(jti.encode("utf-8")).hexdigest()


# RFC 7638 JWK thumbprint: base64url SHA-256 without padding
THUMBPRINT = re.compile(r"[A-Za-z0-9_-]{43}")


def is_valid_kid(kid: str) -> bool:
    """
    Key ID must be a RFC 7638 JWK thumbprint (base64url SHA-256) or uuid4
    in hex format (keys of the 0.x versions)
    """
    if not isinstance(kid, str):
        return False
    if THUMBPRINT.fullmatch(kid):
        return True
    try:
        parsed = uuid.UUID(kid)
        return parsed.version == 4 and parsed.hex == kid
    except ValueError:
        return False


def require_valid_kid(kid: str) -> str:
    """
    A storage uses only valid Key IDs in file names, Vault paths and Redis
    keys (no '../', no other records)

    :returns: kid
    :raises ValueError: invalid Key ID
    """
    if not is_valid_kid(kid):
        raise ValueError(f"Invalid Key ID {kid!r}.")
    return kid
