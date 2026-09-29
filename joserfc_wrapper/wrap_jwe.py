"""joserfc jwe wrapper"""

from joserfc import jwe
from joserfc.jwk import OctKey
from joserfc_wrapper.exceptions import ObjectTypeError
from joserfc_wrapper.token_header import read_kid
from joserfc_wrapper.wrap_jwk import WrapJWK

# the key wrapping and the content encryption used by this library
JWE_ALGORITHMS = ["A128KW", "A128GCM"]


class WrapJWE:
    """
    Encrypt and decrypt custom data

    Safe for threads, one WrapJWE can be shared in the application.
    """

    def __init__(self, wrapjwk: WrapJWK) -> None:
        """
        :param wrapjwk: for non vault storage
        """
        if not isinstance(wrapjwk, WrapJWK):
            raise ObjectTypeError
        self.__jwk = wrapjwk

    def encrypt(self, data: str | bytes, kid: str = "") -> str:
        """
        Encrypt string or bytes with key

        :param data: Secret string or bytes
        :param kid: Key ID, default the last key
        :returns: Encrypted string, the header contains KID of the used key
        :raises TypeError:
        """
        if isinstance(data, (str, bytes)):
            used_kid, secret = self.__jwk.load_secret_key(kid)
            protected = {
                "alg": "A128KW",
                "enc": "A128GCM",
                "kid": used_kid,
            }
            key = OctKey.import_key(secret)
            return jwe.encrypt_compact(protected, data, key)
        raise TypeError("Bad type of data.")

    def decrypt(self, data: str, kid: str = "") -> bytes | None:
        """
        Decrypt string with key

        :param data: Encrypted string
        :param kid: Key ID, default KID from the header of the data,
            the last key for data without KID in the header
        :returns: Decrypted data
        :raises TypeError:
        :raises TokenDecodeError: malformed data
        :raises TokenKidInvalidError: invalid KID in the header
        :raises JoseError: invalid data, other algorithms than A128KW and
            A128GCM, compressed data ('zip')
        """
        if isinstance(data, str):
            if not kid:
                kid = read_kid(data, required=False)
            _, secret = self.__jwk.load_secret_key(kid)
            key = OctKey.import_key(secret)
            # only the algorithms of this library (RFC 8725), no 'zip'
            return jwe.decrypt_compact(
                data, key, algorithms=JWE_ALGORITHMS
            ).plaintext
        raise TypeError("Bad type of data")
