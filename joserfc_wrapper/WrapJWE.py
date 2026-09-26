"""joserfc jwe wrapper"""

from joserfc import jwe
from joserfc.jwk import OctKey
from joserfc_wrapper.Exceptions import ObjectTypeError
from joserfc_wrapper.TokenHeader import read_kid
from joserfc_wrapper.WrapJWK import WrapJWK


class WrapJWE:
    """Encrypt and decrypt custom data"""

    def __init__(self, wrapjwk: WrapJWK) -> None:
        """
        :param wrapjwk: for non vault storage
        :type WrapJWK:
        """
        if not isinstance(wrapjwk, WrapJWK):
            raise ObjectTypeError
        self.__jwk = wrapjwk

    def encrypt(self, data: str | bytes, kid: str = "") -> str:
        """
        Encrypt string or bytes with key

        :param data: Secret string or bytes
        :type str | bytes:
        :param kid: Key ID, default the last key
        :type str:
        :returns: Encrypted string, the header contains KID of the used key
        :rtype str:
        :raise TypeError:
        """
        if isinstance(data, (str, bytes)):
            self.__load_keys(kid)
            protected = {
                "alg": "A128KW",
                "enc": "A128GCM",
                "kid": self.__jwk.get_kid(),
            }
            key = OctKey.import_key(self.__jwk.get_secret_key())
            return jwe.encrypt_compact(protected, data, key)
        raise TypeError("Bad type of data.")

    def decrypt(self, data: str, kid: str = "") -> bytes | None:
        """
        Decrypt string with key

        :param data: Encrypted string
        :type str:
        :param kid: Key ID, default KID from the header of the data,
            the last key for data without KID in the header
        :type str:
        :returns: Decrypted data
        :rtype bytes | None:
        :raise TypeError:
        :raise TokenDecodeError: malformed data
        :raise TokenKidInvalidError: invalid KID in the header
        """
        if isinstance(data, str):
            if not kid:
                kid = read_kid(data, required=False)
            self.__load_keys(kid)
            key = OctKey.import_key(self.__jwk.get_secret_key())
            return jwe.decrypt_compact(data, key).plaintext
        raise TypeError("Bad type of data")

    def __load_keys(self, kid: str) -> None:
        # load keys if not loaded
        self.__jwk.load_keys(kid)
