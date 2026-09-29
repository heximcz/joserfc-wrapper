# joserfc-wrapper

The `joserfc-wrapper` library simplifies the use of JWT and automates the
management of signature keys.

## Features

- JWT tokens signed by ES256 keys (EC P-256) using the
  [joserfc](https://github.com/authlib/joserfc) library, checked against
  the RFCs of JWT (RFC 7519, RFC 8725), token types against confusion of
  tokens.
- Signature keys stored in [HashiCorp Vault](https://www.vaultproject.io/)
  (KV v2 secrets engine, KV v1 is deprecated), [Redis](https://redis.io/),
  on the file system, or in a custom storage.
- Key lifecycle: automatic rotation by age, older tokens stay verifiable,
  revocation of leaked keys, deletion of old keys.
- Revocation of single tokens (logout, leaked tokens).
- JWKS: other services and API gateways verify tokens with the public keys
  only, without access to the private keys. Cached verification keys.
- Encryption of secret data (JWE), for example inside token claims.
- Safe for concurrent processes sharing the same storage and for threads
  sharing one instance.
- `genjw` command line tool for keys and tokens.

## Standards

The behavior is checked against the RFCs of JWT with forged tokens,
details in
[Standards (RFC)](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/standards.md).

| | Topic | Status in 0.9 | Planned change |
| --- | --- | --- | --- |
| [RFC 7519][rfc7519] | JWT | yes | `sub` required (1.0.0) |
| [RFC 7515][rfc7515] | JWS | yes (compact form) | - |
| [RFC 7516][rfc7516] | JWE | yes (compact form) | - |
| [RFC 7517][rfc7517] | JWK, JWK Set | yes | - |
| [RFC 7518][rfc7518] | Algorithms (JWA) | yes, ES256, A128KW | - |
| [RFC 7638][rfc7638] | JWK thumbprint | accepted as `kid` | `kid` of new keys (1.0.0) |
| [RFC 8725][rfc8725] | JWT best practices | yes | - |
| [RFC 9068][rfc9068] | JWT access tokens | partly, optional profile | `sub` required (1.0.0) |
| [RFC 9864][rfc9864] | Fully specified algorithms | yes, ES256 | - |

JWS and JWE in the compact form (a JWT), the JSON serialization is not
supported. RFC 9068 is an optional profile of OAuth 2.0 access tokens:
tokens follow it with `token_type="at+jwt"` and your own `client_id` claim,
but the library supports only ES256 and the profile requires also RS256.

[rfc7519]: https://www.rfc-editor.org/rfc/rfc7519
[rfc7515]: https://www.rfc-editor.org/rfc/rfc7515
[rfc7516]: https://www.rfc-editor.org/rfc/rfc7516
[rfc7517]: https://www.rfc-editor.org/rfc/rfc7517
[rfc7518]: https://www.rfc-editor.org/rfc/rfc7518
[rfc7638]: https://www.rfc-editor.org/rfc/rfc7638
[rfc8725]: https://www.rfc-editor.org/rfc/rfc8725
[rfc9068]: https://www.rfc-editor.org/rfc/rfc9068
[rfc9864]: https://www.rfc-editor.org/rfc/rfc9864

## Install

Requires Python 3.10 or newer.

```bash
pip install joserfc-wrapper
```

With HashiCorp Vault or Redis install the optional dependency of the
storage: `pip install "joserfc-wrapper[vault]"` or
`pip install "joserfc-wrapper[redis]"` (the Vault client is installed always
until 0.9.x, only with the `vault` extra in 1.0.0).

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

# create a token for a user ('iss', 'aud', 'exp' and 'jti' are added
# automatically)
token = jwt.create(claims={"sub": "123"})

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
- [Standards (RFC)](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/standards.md)
- [Preparing for 1.0.0](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/upgrading.md#preparing-for-100)
- [Upgrading from 0.8.x](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/upgrading.md#upgrading-from-08x)
- [Upgrading from 0.7.x](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/upgrading.md#upgrading-from-07x)
- [Upgrading from 0.6.x](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/upgrading.md#upgrading-from-06x)
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
