# joserfc-wrapper

The `joserfc-wrapper` library simplifies the use of JWT and automates the
management of signature keys.

## Features

- JWT tokens signed by ES256 keys (EC P-256) using the
  [joserfc](https://github.com/authlib/joserfc) library and adhering to RFC
  standards.
- Signature keys stored in [HashiCorp Vault](https://www.vaultproject.io/)
  (KV v2 or KV v1 secrets engine) or on the file system, or in a custom
  storage.
- Automatic key rotation after a given number of signed tokens, older tokens
  stay verifiable.
- Encryption of secret data (JWE), for example inside token claims.
- Safe for concurrent processes sharing the same storage.
- `genjw` command line tool for keys and tokens.

## Install

Requires Python 3.10 or newer.

```bash
pip install joserfc-wrapper
```

We recommend installing it in a virtual environment, which isolates the
dependencies of your project from the rest of your system:

```bash
python -m venv .venv
source .venv/bin/activate
pip install joserfc-wrapper
```

## Quick start

```python
from joserfc_wrapper import StorageFile, WrapJWK, WrapJWT

storage = StorageFile(cert_dir="/etc/myapp/keys")

# create the first signature keys (only once)
jwk = WrapJWK(storage)
jwk.generate_keys()
jwk.save_keys()

# create a token, it expires after 1 hour
jwt = WrapJWT(jwk)
token = jwt.create(
    claims={"iss": "https://example.com", "aud": "auditor", "uid": 123},
    exp=3600,
)

# verify the signature and the claims
decoded = jwt.decode(token)
if jwt.validate(decoded, {"iss": "https://example.com", "aud": "auditor"}):
    print(decoded.claims)
```

## Custom storage

A custom storage, for example a database, must be a subclass of the
[AbstractKeyStorage](https://github.com/heximcz/joserfc-wrapper/blob/main/joserfc_wrapper/AbstractKeyStorage.py)
abstract class and implement the necessary methods. For concurrent processes
override also `increase_counter` and `replace_last_keys` with atomic
implementations.

## Documentation

- [Library](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/index.md)
- [CLI](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/cli.md)
- [Security notes for developers](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/security.md)
- [Upgrading from 0.2.x](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/index.md#upgrading-from-02x)

## License

- [joserfc_wrapper](https://github.com/heximcz/joserfc-wrapper/blob/main/LICENSE)
  (MIT)
- [joserfc](https://github.com/authlib/joserfc?tab=readme-ov-file#license)
  (BSD-3)

## Contributions

Contributions to the development of this library are welcome, ideally in the
form of a pull request.
