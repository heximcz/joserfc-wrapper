# joserfc-wrapper

The `joserfc-wrapper` library simplifies the use of JWT and automates the
management of signature keys.

## Version 1.0.0

1.0.0 is not backward compatible with the 0.x series. The versions before
1.0.0 were the development branch of the project. Backward compatibility is
kept since 1.0.0: the library follows
[semantic versioning](https://semver.org/), incompatible changes come only
in a new major version, see
[Upgrading from 0.x to 1.0.0](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/upgrading.md#upgrading-from-0x-to-100).

## Features

- JWT tokens signed by ES256 (EC P-256) or Ed25519 keys using the
  [joserfc](https://github.com/authlib/joserfc) library, checked against
  the RFCs of JWT (RFC 7519, RFC 8725), token types against confusion of
  tokens.
- Signature keys stored in [HashiCorp Vault](https://www.vaultproject.io/)
  (KV v2 secrets engine), [Redis](https://redis.io/), on the file system,
  or in a custom storage.
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

| | Topic | Status |
| --- | --- | --- |
| [RFC 7519][rfc7519] | JWT | yes, `sub` required |
| [RFC 7515][rfc7515] | JWS | yes (compact form) |
| [RFC 7516][rfc7516] | JWE | yes (compact form) |
| [RFC 7517][rfc7517] | JWK, JWK Set | yes |
| [RFC 7518][rfc7518] | Algorithms (JWA) | yes, ES256, A128KW, A128GCM |
| [RFC 7638][rfc7638] | JWK thumbprint | yes, the `kid` of keys |
| [RFC 8037][rfc8037] | Ed25519 (OKP keys) | yes |
| [RFC 8725][rfc8725] | JWT best practices | yes |
| [RFC 9068][rfc9068] | JWT access tokens | partly, optional profile |
| [RFC 9864][rfc9864] | Fully specified algorithms | yes, ES256, Ed25519 |

JWS and JWE in the compact form (a JWT), the JSON serialization is not
supported. RFC 9068 is an optional profile of OAuth 2.0 access tokens:
tokens follow it with `token_type="at+jwt"` and your own `client_id` claim,
but the profile requires also RS256.

**RS256 (RSA) is not supported and will never be supported**, the library
signs tokens only by ES256 and Ed25519.

[rfc7519]: https://www.rfc-editor.org/rfc/rfc7519
[rfc7515]: https://www.rfc-editor.org/rfc/rfc7515
[rfc7516]: https://www.rfc-editor.org/rfc/rfc7516
[rfc7517]: https://www.rfc-editor.org/rfc/rfc7517
[rfc7518]: https://www.rfc-editor.org/rfc/rfc7518
[rfc7638]: https://www.rfc-editor.org/rfc/rfc7638
[rfc8037]: https://www.rfc-editor.org/rfc/rfc8037
[rfc8725]: https://www.rfc-editor.org/rfc/rfc8725
[rfc9068]: https://www.rfc-editor.org/rfc/rfc9068
[rfc9864]: https://www.rfc-editor.org/rfc/rfc9864

## Install

Requires Python 3.11 or newer.

```bash
pip install joserfc-wrapper
```

With HashiCorp Vault or Redis install the optional dependency of the
storage: `pip install "joserfc-wrapper[vault]"` or
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

# once for the application, safe for threads
jwk = WrapJWK(storage)
# the rules of your tokens, tokens expire after 1 hour
jwt = WrapJWT(
    jwk, issuer="https://example.com", audience="api", default_exp=3600
)

# create the first signature keys (a next call rotates them)
jwk.rotate()

# create a token for a user, 'sub' is required ('iss', 'aud', 'exp' and
# 'jti' are added automatically)
token = jwt.create(claims={"sub": "123"})

# verify the signature, exp, iss, aud and sub, raises InvalidTokenError
print(jwt.verify(token).claims)
```

## Custom storage

A custom storage, for example a database, must be a subclass of the
[AbstractKeyStorage](https://github.com/heximcz/joserfc-wrapper/blob/main/joserfc_wrapper/abstract_key_storage.py)
abstract class and implement its abstract methods, `replace_last_keys` and
`update_metadata` atomically (safe for concurrent processes).
`joserfc_wrapper.testing.check_storage` tests that a custom storage keeps
the contract.

## Documentation

Full documentation: <https://joserfc-wrapper.readthedocs.io/>

- [Library](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/index.md)
- [CLI](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/cli.md)
- [Security notes for developers](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/security.md)
- [Standards (RFC)](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/standards.md)
- [Upgrading from 0.x to 1.0.0](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/upgrading.md#upgrading-from-0x-to-100)
- [Upgrading between 0.x versions](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/upgrading.md)

## License

- [joserfc_wrapper](https://github.com/heximcz/joserfc-wrapper/blob/main/LICENSE)
  (MIT)
- [joserfc](https://github.com/authlib/joserfc?tab=readme-ov-file#license)
  (BSD-3)

## Contributions

Contributions to the development of this library are welcome, ideally in the
form of a pull request.
