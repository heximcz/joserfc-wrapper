# joserfc-wrapper

The `joserfc-wrapper` library simplifies the use of JWT and automates the
management of signature keys.

## Features

- JWT tokens signed by ES256 keys (EC P-256) using the
  [joserfc](https://github.com/authlib/joserfc) library and adhering to RFC
  standards.
- Signature keys stored in [HashiCorp Vault](https://www.vaultproject.io/)
  (KV v2 secrets engine, KV v1 is deprecated), [Redis](https://redis.io/),
  on the file system, or in a custom storage.
- Key lifecycle: automatic rotation by age, older tokens stay verifiable,
  revocation of leaked keys, deletion of old keys.
- Revocation of single tokens (logout, leaked tokens).
- Encryption of secret data (JWE), for example inside token claims.
- Safe for concurrent processes sharing the same storage.
- `genjw` command line tool for keys and tokens.

## Install

Requires Python 3.10 or newer.

```bash
pip install joserfc-wrapper
```

For the Redis storage install the optional dependency:
`pip install "joserfc-wrapper[redis]"`.

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

# create the first signature keys (a next call rotates them)
jwk = WrapJWK(storage)
jwk.rotate()

# the rules of your tokens, tokens expire after 1 hour
jwt = WrapJWT(
    jwk, issuer="https://example.com", audience="api", default_exp=3600
)

# create a token ('iss', 'aud', 'exp' and 'jti' are added automatically)
token = jwt.create(claims={"uid": 123})

# verify the signature, exp, iss and aud, raises InvalidTokenError
print(jwt.verify(token).claims)
```

## Custom storage

A custom storage, for example a database, must be a subclass of the
[AbstractKeyStorage](https://github.com/heximcz/joserfc-wrapper/blob/main/joserfc_wrapper/AbstractKeyStorage.py)
abstract class and implement the necessary methods. For concurrent processes
override also `increase_counter`, `replace_last_keys` and `update_metadata`
with atomic implementations. `joserfc_wrapper.testing.check_storage` tests
that a custom storage keeps the contract.

## Documentation

Full documentation: <https://joserfc-wrapper.readthedocs.io/>

- [Library](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/index.md)
- [CLI](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/cli.md)
- [Security notes for developers](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/security.md)
- [Upgrading from 0.5.x](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/upgrading.md#upgrading-from-05x)
- [Upgrading from 0.4.x](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/upgrading.md#upgrading-from-04x)
- [Upgrading from 0.3.x](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/upgrading.md#upgrading-from-03x)
- [Upgrading from 0.2.x](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/upgrading.md#upgrading-from-02x)

## License

- [joserfc_wrapper](https://github.com/heximcz/joserfc-wrapper/blob/main/LICENSE)
  (MIT)
- [joserfc](https://github.com/authlib/joserfc?tab=readme-ov-file#license)
  (BSD-3)

## Contributions

Contributions to the development of this library are welcome, ideally in the
form of a pull request.
