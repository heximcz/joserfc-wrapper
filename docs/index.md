# joserfc-wrapper

`joserfc-wrapper` simplifies the use of JWT and automates the management of
signature keys: ES256 tokens, keys stored in HashiCorp Vault or on the file
system, automatic key rotation, encrypted data (JWE) and the `genjw` command
line tool. Requires Python 3.10 or newer.

Before using the library to protect an API, read the
[security notes for developers](./security.md).

## Contents

- [Getting started](./getting-started.md): install, quick start
- [Storages](./storage.md): files, HashiCorp Vault, custom storage
- [Signature keys](./keys.md): creating keys, key rotation
- [Tokens](./tokens.md): configuration, creating tokens, claims, `jti`
- [Verifying tokens](./verify.md): `verify`, exceptions (401 vs 500)
- [Encrypted data (JWE)](./jwe.md)
- [Security notes for developers](./security.md)
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
