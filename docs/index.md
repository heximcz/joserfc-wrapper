# Documentation

Documentation for version 0.3.0. Requires Python 3.10 or newer.

## Import

```python
from joserfc_wrapper import (
    StorageFile,
    StorageVault,
    WrapJWE,
    WrapJWK,
    WrapJWT,
)
```

## Storage configuration

All processes and services which create or verify tokens share the same
storage with the signing keys.

```python
# file storage, the directory must exist
storage = StorageFile(cert_dir="/etc/myapp/keys")

# HashiCorp Vault storage, KV v2 secrets engine (default)
storage = StorageVault(
    url="<vault url>",
    token="<token>",
    mount="<secure mount>",
)

# KV v1 secrets engine (keys saved by versions older than 0.3.0),
# not safe for concurrent processes
storage = StorageVault(
    url="<vault url>",
    token="<token>",
    mount="<secure mount>",
    kv_version=1,
)
```

`StorageFile` saves each key to `<kid>.json` and the last Key ID to
`last-key-id.json`, both readable only by the owner (`0600`). Writes are
atomic and locked by the `.lock` file in the same directory.

A KV v2 mount for `StorageVault` can be created by:

```bash
vault secrets enable -path=jwt -version=2 kv
```

## Header and claims in this wrapper

```python
# decoded header (all created automatically)
{
    "typ": "JWT",
    "alg": "ES256",
    "kid": "cdfef1a0e8414b25a593e50c47e59dcb",  # Key ID
}
# decoded claims
{
    "iss": "https://example.com",  # required, str
    "aud": "auditor",  # required, str
    "uid": 123,  # required, int
    "iat": 1705418960,  # created automatically
    "exp": 1705422560,  # optional, see the 'exp' parameter
}
```

Other claims are added to the token unchanged.

## Create new signature keys

At least one key must exist in the storage before the first token is
created. The new keys become the last keys, which sign new tokens.

```python
myjwk = WrapJWK(storage=storage)

# generate new keys (EC P-256 for signing, oct 128 bits for JWE)
myjwk.generate_keys()
# save new keys to the storage
myjwk.save_keys()
```

## Define required claims

```python
claims = {
    "iss": "https://example.com",
    "aud": "auditor",
    "uid": 123,
}
```

## Create token

```python
try:
    myjwt = WrapJWT(wrapjwk=myjwk)
    # a new token is always signed by the last keys in the storage
    token = myjwt.create(claims=claims)
    print(f"Token: {token[:20]}..., Length: {len(token)} bytes")
except Exception as e:
    print(f"{type(e).__name__}: {e}")
```

A token without `exp` is valid as long as its signing key exists in the
storage. Set the expiration by the `exp` parameter (seconds), it adds the
`exp` claim as `iat + exp`:

```python
# token expires after 1 hour
token = myjwt.create(claims=claims, exp=3600)
```

The `exp` claim can be also set directly in claims, but not both.

## Create token with encrypted data

```python
try:
    myjwe = WrapJWE(wrapjwk=myjwk)

    # encrypt secret data (str or bytes) by the last keys,
    # the Key ID is saved in the header of the encrypted data
    claims_with_sec = {
        **claims,
        "sec": myjwe.encrypt(data="very secret text"),
        "sec_bytes": myjwe.encrypt(data=b"very secret bytes"),
    }

    myjwt = WrapJWT(wrapjwk=myjwk)
    token_with_sec = myjwt.create(claims=claims_with_sec)
except Exception as e:
    print(f"{type(e).__name__}: {e}")
```

## Token validation

`decode` selects the key by `kid` in the token header and verifies the
signature by the public key. It does not check the claims, call `validate`
after it.

```python
try:
    myjwt = WrapJWT(wrapjwk=myjwk)
    # returns joserfc Token object
    valid_token = myjwt.decode(token=token)
    print(valid_token.header)
    print(valid_token.claims)
except Exception as e:
    print(f"{type(e).__name__}: {e}")

# the claims must be equal in the token, returns False for missing or
# invalid claims and for an expired ('exp') or not yet valid ('nbf') token
if myjwt.validate(
    token=valid_token,
    claims={"iss": "https://example.com", "aud": "auditor"},
):
    print("Token is valid.")
```

## Invalid tokens

```python
from joserfc.errors import JoseError
from joserfc_wrapper import (
    KeysLoadError,
    TokenDecodeError,
    TokenKidInvalidError,
)

try:
    myjwt = WrapJWT(wrapjwk=myjwk)
    valid_token = myjwt.decode(token=token)
except TokenDecodeError:
    # malformed token
    pass
except TokenKidInvalidError:
    # missing or invalid kid in the token header
    pass
except KeysLoadError as e:
    # kid is not in the storage, the original storage error
    # (FileNotFoundError, hvac InvalidPath) is available as e.__cause__
    pass
except JoseError:
    # invalid signature (joserfc.errors.BadSignatureError) and others
    pass
```

## Decrypt secret data

```python
try:
    myjwt = WrapJWT(wrapjwk=myjwk)
    valid_token = myjwt.decode(token=token_with_sec)

    myjwe = WrapJWE(wrapjwk=myjwk)
    # the key is selected by kid in the header of the encrypted data,
    # data encrypted by versions older than 0.3.0 have no kid in the
    # header, they are decrypted by the last keys or by the kid parameter
    secret_data = myjwe.decrypt(valid_token.claims["sec"])
    secret_data_bytes = myjwe.decrypt(valid_token.claims["sec_bytes"])
    print(f"[sec]: {secret_data}")  # b'very secret text'
    print(f"[sec_bytes]: {secret_data_bytes}")  # b'very secret bytes'
except Exception as e:
    print(f"{type(e).__name__}: {e}")
```

## Key rotation

By default (`payload=0`) the keys are never rotated automatically and a single
key signs an unlimited number of tokens. The `payload` parameter sets the
maximum number of tokens signed by a key. When the key reaches it, new keys
are generated and saved as the last keys. If a key is leaked or compromised,
only a limited number of tokens is affected.

```python
token = myjwt.create(claims=claims, payload=10)
```

The old keys stay in the storage, so older tokens and encrypted data can be
still verified and decrypted. The keys are never deleted, so each rotation
adds new keys to the storage. Choose the payload with this in mind.

The counter of signed tokens is saved for every token, also with the default
`payload=0`. After increasing the payload, the keys are rotated by the real
number of tokens signed by the key.

Keys can be rotated manually by `generate_keys` and `save_keys`.

## Concurrent processes

More processes can sign tokens with the same storage. The counter is
increased atomically and the keys are rotated only once, so a key never signs
more than `payload` tokens:

- `StorageFile` locks writes with `fcntl.flock` on the `.lock` file in
  `cert_dir` (not on Windows, not reliable on NFS).
- `StorageVault` with KV v2 uses check-and-set. KV v1 is not atomic.
- A custom storage is atomic only when it overrides `increase_counter` and
  `replace_last_keys`, see below.

`WrapJWK` keeps the loaded keys, create a new `WrapJWK` and `WrapJWT` for each
thread.

## Custom storage

A custom storage, for example a database, must be a subclass of
[`AbstractKeyStorage`](../joserfc_wrapper/AbstractKeyStorage.py)
and implement:

- `get_last_kid()` - the last Key ID
- `load_keys(kid="")` - returns `(kid, {"data": keys})`, the last keys for
  an empty `kid`
- `save_keys(kid, keys)` - saves the keys and sets them as the last keys
- `_save_last_id(kid)` - sets the last Key ID

The keys have this format:

```python
{
    "keys": {"private": dict, "public": dict, "secret": dict},
    "counter": int,
}
```

For concurrent processes override also `increase_counter(kid, limit)` and
`replace_last_keys(last_kid, kid, keys)` with atomic implementations. The
default implementations use the methods above and are not atomic.

## Exceptions

All exceptions of this library are subclasses of `WrapperErrors`:

- `KeysLoadError`, `KeysSaveError` - storage errors (missing keys, file
  system, Vault), the original exception is available as `__cause__`
- `KeysNotLoadedError` - `WrapJWK` getters called before `load_keys` or
  `generate_keys`
- `GenerateKeysError` - key generation failed
- `TokenDecodeError`, `TokenKidInvalidError` - malformed token or invalid
  `kid` in the header
- `CreateTokenException` - missing or invalid required claims or `exp`
- `ObjectTypeError` - invalid object passed to a constructor

Invalid signatures and other token errors are raised by joserfc:

- [joserfc exceptions](https://github.com/authlib/joserfc/blob/main/src/joserfc/errors.py)
- [hvac exceptions](https://hvac.readthedocs.io/en/stable/source/hvac_exceptions.html)
- [joserfc_wrapper exceptions](../joserfc_wrapper/Exceptions.py)

## Upgrading from 0.2.x

- `StorageVault` uses KV v2 by default. Keys saved in a KV v1 mount require
  `kv_version=1` (CLI `VAULT_KV_VERSION=1`), or move them to a KV v2 mount.
- `validate` returns `False` for invalid values of claims and for expired
  tokens instead of raising `InvalidClaimError` and `ExpiredTokenError`.
- `decode` raises `TokenDecodeError` for a malformed token instead of
  `ValueError` or `KeyError`. `kid` must be a uuid4 in hex format.
- Storage errors are raised as `KeysLoadError` and `KeysSaveError` instead of
  `FileNotFoundError`, hvac `InvalidPath` and others.
- `WrapJWK` getters raise `KeysNotLoadedError` instead of `AttributeError`.
- `uid=True` is rejected, `create` does not modify the passed claims.
- JWE data contain `kid` in the header, `decrypt` does not need the `kid`
  parameter.
- `StorageFile` saves files with `0600` permissions and creates the `.lock`
  file in `cert_dir`.
- `StorageVault` has no `token` attribute. `load_keys` with KV v1 returns
  only `{"data": ...}` instead of the whole Vault response.
- CLI prints errors to stderr and exits with code 1.

## CLI

[CLI documentation.](./cli.md)

## Contributions

Contributions to the development of this library are welcome, ideally in the
form of a pull request.
