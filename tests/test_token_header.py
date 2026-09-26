import base64
import json
import uuid

import pytest

from joserfc_wrapper import TokenDecodeError, TokenKidInvalidError
from joserfc_wrapper.TokenHeader import is_valid_kid, read_header, read_kid

KID = uuid.uuid4().hex


def token(header: dict) -> str:
    raw = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
    return f"{raw.decode()}.payload.signature"


def test_read_header():
    assert read_header(token({"alg": "ES256", "kid": KID})) == {
        "alg": "ES256",
        "kid": KID,
    }


def test_read_kid():
    assert read_kid(token({"kid": KID})) == KID


def test_read_kid_not_required():
    assert read_kid(token({"alg": "ES256"}), required=False) == ""


@pytest.mark.parametrize(
    "header",
    [{}, {"kid": 1}, {"kid": "not-uuid"}, {"kid": "../" + KID}],
)
def test_read_kid_invalid(header):
    with pytest.raises(TokenKidInvalidError):
        read_kid(token(header))


def test_invalid_kid_not_required():
    with pytest.raises(TokenKidInvalidError):
        read_kid(token({"kid": "not-uuid"}), required=False)


@pytest.mark.parametrize(
    "kid, valid",
    [
        (KID, True),
        (KID.upper(), False),
        (str(uuid.UUID(KID)), False),
        ("{" + KID + "}", False),
        (uuid.uuid1().hex, False),
        ("", False),
    ],
)
def test_is_valid_kid(kid, valid):
    assert is_valid_kid(kid) is valid


def test_read_header_not_object():
    with pytest.raises(TokenDecodeError):
        read_header("WzFd.b.c")  # [1]
