# joserfc-wrapper

`joserfc-wrapper` simplifies the use of JWT and automates the management of
signature keys: ES256 and Ed25519 tokens, keys stored in HashiCorp Vault,
Redis or on the file system, automatic key rotation, revocation of keys and
tokens, JWKS for services which only verify tokens, encrypted data (JWE) and
the `genjw` command line tool. Requires Python 3.11 or newer.

1.0.0 is not backward compatible with the 0.x versions (the development
branch), see [Upgrading from 0.x to 1.0.0](./upgrading.md#upgrading-from-0x-to-100).

Before using the library to protect an API, read the
[security notes for developers](./security.md).

## Contents

- [Getting started](./getting-started.md): install, quick start
- [Storages](./storage.md): files, HashiCorp Vault, Redis, cache of
  verification keys, custom storage
- [Signature keys](./keys.md): creating keys, algorithms, key rotation
- [Tokens](./tokens.md): configuration, creating tokens, claims, `jti`
- [Verifying tokens](./verify.md): `verify`, revoking tokens, exceptions
  (401 vs 500)
- [Verifying services (JWKS)](./jwks.md): public keys for other services
  and API gateways, `StorageJWKS`
- [Encrypted data (JWE)](./jwe.md)
- [Security notes for developers](./security.md)
- [Standards (RFC)](./standards.md): how the library follows the RFCs of
  JWT
- [CLI](./cli.md): the `genjw` command
- [Upgrading](./upgrading.md)
- [API reference](./api.md)

## Upgrading from 0.3.x

Moved to [Upgrading](./upgrading.md#upgrading-from-03x).

## Upgrading from 0.2.x

Moved to [Upgrading](./upgrading.md#upgrading-from-02x).

## Contributions

Contributions to the development of this library are welcome, ideally in the
form of a pull request.
