# Getting started

Requires Python 3.10 or newer.

## Install

```bash
pip install joserfc-wrapper
```

For the Redis storage install the optional dependency:

```bash
pip install "joserfc-wrapper[redis]"
```

We recommend installing it in a virtual environment:

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

The same with HashiCorp Vault or Redis: use `StorageVault` or
`StorageRedis` instead of `StorageFile`, see [Storages](./storage.md).
Create the storage, `WrapJWK` and `WrapJWT` once and share them in the
application, they are safe for threads. Services which
only verify tokens can use `StorageJWKS`, see
[Verifying services (JWKS)](./jwks.md).

## Import

```python
from joserfc_wrapper import (
    StorageFile,
    StorageJWKS,
    StorageRedis,
    StorageVault,
    WrapJWE,
    WrapJWK,
    WrapJWT,
)
```

[Contents](./index.md) |
[Next: Storages >](./storage.md)
