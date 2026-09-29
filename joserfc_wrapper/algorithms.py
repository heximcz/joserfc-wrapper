"""signature algorithms of the keys"""

from joserfc.jwk import ECKey, OKPKey

from joserfc_wrapper.exceptions import ConfigurationError

#: signature algorithms: algorithm -> (kty, crv) of the key (RS256 is not
#: and will never be supported)
ALGORITHMS = {"ES256": ("EC", "P-256"), "Ed25519": ("OKP", "Ed25519")}

SEPARATOR = ", "

#: the algorithm of new keys
DEFAULT_ALGORITHM = "ES256"


def key_algorithm(key: dict) -> str:
    """
    Return the signature algorithm of a key (JWK dict)

    The algorithm belongs to the key, never to the header of a token.

    :raises ValueError: an unsupported key
    """
    for algorithm, (kty, crv) in ALGORITHMS.items():
        if key.get("kty") == kty and key.get("crv") == crv:
            return algorithm
    kty, crv = key.get("kty"), key.get("crv")
    raise ValueError(f"Unsupported key: kty {kty!r}, crv {crv!r}.")


def import_key(key: dict) -> ECKey | OKPKey:
    """
    Import a signature key (JWK dict) of a supported algorithm

    :raises ValueError: an unsupported or invalid key
    """
    if key_algorithm(key) == "Ed25519":
        return OKPKey.import_key(key)
    return ECKey.import_key(key)


def check_algorithm(algorithm: str) -> str:
    """
    :returns: algorithm
    :raises ConfigurationError: unsupported algorithm
    """
    if algorithm not in ALGORITHMS:
        raise ConfigurationError(
            f"Unsupported algorithm {algorithm!r}, use one of "
            f"{SEPARATOR.join(ALGORITHMS)}."
        )
    return algorithm
