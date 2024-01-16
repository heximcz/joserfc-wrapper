from joserfc import jwe
from joserfc.jwk import OctKey
from joserfc_wrapper.exceptions import ObjectTypeError
from joserfc_wrapper import WrapJWK


class WrapJWE:
    def __init__(self, wrapjwk: WrapJWK = WrapJWK()) -> None:
        """
        Encrypt and decrypt custom data in claims

        :param wrapjwk: by default new instance
        :type WrapJWK:
        """
        if not isinstance(wrapjwk, WrapJWK):
            raise ObjectTypeError

        self.__jwk = wrapjwk


    def encrypt(self, data: str, kid: str = None) -> str:
        """
        Encrypt string with key

        :param data: Secret string
        :type str:
        :returns: Encrypted strig with last valid key
        :rtype str:
        :raise TypeError:
        """
        if isinstance(data, str):
            self.__load_keys(kid)
            # encrypt with last key
            protected = {"alg": "A128KW", "enc": "A128GCM"}
            key = OctKey.import_key(self.__jwk.get_secret_key())
            return jwe.encrypt_compact(protected, data, key)
        raise TypeError(f"Bad type of data.")

    def decrypt(self, data: str, kid: str = None) -> str:
        """
        Decrypt string with key

        :param data: Secret string
        :type str:
        :returns: Decrypted strig with last valid key
        :rtype str:
        :raise TypeError:
        """
        if isinstance(data, str):
            self.__load_keys(kid)
            key = OctKey.import_key(self.__jwk.get_secret_key())
            return jwe.decrypt_compact(data, key).plaintext
        raise TypeError(f"Bad type of data")

    def __load_keys(self, kid: str) -> None:
        # load keys if not loaded
        self.__jwk.load_keys(kid)
