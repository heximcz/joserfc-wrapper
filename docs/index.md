# Documentation

Documentation for version 0.4.0. Requires Python 3.10 or newer.

Before using the library to protect an API, read the
[security notes for developers](./security.md).

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
    "iss": "https://example.com",  # required, str (or issuer of WrapJWT)
    "aud": "api",  # required, str or list (or audience of WrapJWT)
    "uid": 123,  # required, int
    "jti": "5b0be60b1c91438e9f5c0a6c1b2d3e4f",  # unique token ID, automatic
    "iat": 1705418960,  # created automatically
    "exp": 1705422560,  # expiration, required by verify
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

## Configure tokens

Set the rules of your tokens once, `create` and `verify` use them:

```python
myjwt = WrapJWT(
    wrapjwk=myjwk,
    issuer="https://example.com",  # 'iss', required by verify
    audience="api",  # 'aud', str or list of allowed values, required by verify
    default_exp=3600,  # create without exp: the token expires after 1 hour
    max_age=None,  # optional: a token is expired max_age seconds after 'iat'
    leeway=0,  # tolerance of clocks in seconds
)
```

## Create token

```python
try:
    # a new token is always signed by the last keys in the storage,
    # 'iss' and 'aud' are added from WrapJWT, 'jti' is added automatically
    token = myjwt.create(claims={"uid": 123})
    print(f"Token: {token[:20]}..., Length: {len(token)} bytes")
except Exception as e:
    print(f"{type(e).__name__}: {e}")
```

- `exp` (seconds) overrides `default_exp`: `myjwt.create(claims, exp=600)`.
  The `exp` claim can be also set directly in claims, but not both.
- A token without `exp` is invalid for `verify`, create tokens with `exp`
  or set `default_exp`.
- `iss` or `aud` in claims must match `issuer` and `audience` of WrapJWT,
  otherwise `CreateTokenException`.
- `jti` (unique token ID) is added when it is not in the claims, a custom
  `jti` must be a non-empty string. `myjwt.get_jti(token)` returns it after
  verifying the signature, for example for logging.

## Create token with encrypted data

```python
try:
    myjwe = WrapJWE(wrapjwk=myjwk)

    # encrypt secret data (str or bytes) by the last keys,
    # the Key ID is saved in the header of the encrypted data
    claims_with_sec = {
        "uid": 123,
        "sec": myjwe.encrypt(data="very secret text"),
        "sec_bytes": myjwe.encrypt(data=b"very secret bytes"),
    }

    token_with_sec = myjwt.create(claims=claims_with_sec)
except Exception as e:
    print(f"{type(e).__name__}: {e}")
```

## Verify token

`verify` checks everything in one call: the signature (the key is selected
by `kid` in the token header), `exp` (required), `nbf`, `iat`, `iss`, `aud`
and `max_age`. It returns the token or raises an exception with the reason.

```python
from joserfc_wrapper import InvalidTokenError, KeysLoadError

try:
    token = myjwt.verify(token)
    print(token.header, token.claims)
except InvalidTokenError as e:
    # invalid token: HTTP 401, log the reason (never the whole token)
    print(f"{type(e).__name__}: {e}")
except KeysLoadError:
    # storage failure (e.g. Vault is not available): HTTP 500
    raise
```

Other claims which must be equal in the token:

```python
token = myjwt.verify(token, claims={"role": "admin"})
```

`InvalidTokenError` subclasses, when you need the exact reason:

- `TokenDecodeError`: malformed token
- `TokenKidInvalidError`: missing or invalid `kid` in the header
- `TokenKidUnknownError`: `kid` is not in the storage
- `TokenSignatureError`: invalid signature
- `TokenExpiredError`: expired token (`exp` or `max_age`)
- `TokenNotYetValidError`: `nbf` in the future
- `TokenClaimError`: missing or invalid claim (`exp`, `iss`, `aud`, ...)

`verify` raises `ConfigurationError` when `issuer` or `audience` of WrapJWT
is not set.

`decode` verifies only the signature and does not check any claim. Use it
only to show a token (like `genjw show`), never to accept a token.

`validate` is deprecated since 0.4.0 (`DeprecationWarning`) and will be
removed in 1.0.0, use `verify`.

## Decrypt secret data

```python
try:
    valid_token = myjwt.verify(token_with_sec)

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
token = myjwt.create(claims={"uid": 123}, payload=10)
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

- `InvalidTokenError` and its subclasses - invalid token (HTTP 401), see
  [Verify token](#verify-token)
- `KeysLoadError`, `KeysSaveError` - storage errors (file system, Vault),
  the original exception is available as `__cause__`
- `KeysNotFoundError` - subclass of `KeysLoadError`, the keys are not in
  the storage (`verify` raises `TokenKidUnknownError` instead)
- `KeysNotLoadedError` - `WrapJWK` getters called before `load_keys` or
  `generate_keys`
- `GenerateKeysError` - key generation failed
- `CreateTokenException` - missing or invalid claims or `exp`
- `ConfigurationError` - invalid parameters of `WrapJWT`, or `verify`
  without `issuer` and `audience`
- `ObjectTypeError` - invalid object passed to a constructor

Source of the exceptions and of the storage errors in `__cause__`:

- [hvac exceptions](https://hvac.readthedocs.io/en/stable/source/hvac_exceptions.html)
- [joserfc_wrapper exceptions](../joserfc_wrapper/Exceptions.py)

## Upgrading from 0.3.x

- New `WrapJWT.verify` replaces `decode` + `validate`. `validate` is
  deprecated (`DeprecationWarning`) and will be removed in 1.0.0.
- A token without `exp` is invalid, also for `validate`. Create tokens with
  `exp` or set `default_exp` of WrapJWT.
- CLI: `genjw token` requires `--exp`, `genjw check` uses `verify` (a token
  without `exp` is invalid) and prints the reason.
- `TokenDecodeError` and `TokenKidInvalidError` are subclasses of the new
  `InvalidTokenError` (still subclasses of `WrapperErrors`).
- A missing key raises `KeysNotFoundError`, a subclass of `KeysLoadError`.
- Tokens contain the `jti` claim (unique token ID).
- `iss` or `aud` in the claims of `create` different from `issuer` or
  `audience` of WrapJWT raise `CreateTokenException`.

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
