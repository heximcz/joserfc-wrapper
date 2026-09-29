# Verifying tokens

Verify every token by `verify` before you accept it, see also the
[security notes](./security.md).

## Verify token

`verify` checks everything in one call: the signature (the key is selected
by `kid` in the token header), `exp` (required), `nbf`, `iat`, `iss`, `aud`
and `max_age`. It returns the token or raises an exception with the reason.
The public keys are cached by the storage object, see
[Cache of verification keys](./storage.md#cache-of-verification-keys).
Services which only verify tokens can use the JWKS instead of the storage,
see [Verifying services (JWKS)](./jwks.md).

```python
from joserfc_wrapper import InvalidTokenError, KeysLoadError

try:
    # token is the string from create (or from the Authorization header)
    verified = myjwt.verify(token)
    print(verified.header, verified.claims)
except InvalidTokenError as e:
    # invalid token: HTTP 401, log the reason (never the whole token)
    print(f"{type(e).__name__}: {e}")
except KeysLoadError:
    # storage failure (e.g. Vault is not available): HTTP 500
    raise
```

Other claims which must be equal in the token:

```python
admin_token = myjwt.create(claims={"uid": 123, "role": "admin"})
verified = myjwt.verify(admin_token, claims={"role": "admin"})
```

`InvalidTokenError` subclasses, when you need the exact reason:

- `TokenDecodeError`: malformed token
- `TokenKidInvalidError`: missing or invalid `kid` in the header
- `TokenKidUnknownError`: `kid` is not in the storage
- `TokenKeyRevokedError`: the key of the token is revoked
- `TokenRevokedError`: the token is revoked, see
  [Revoke tokens](#revoke-tokens)
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

## Revoke tokens

A single token can be revoked, for example after a logout or when a token
leaks. Enable it by `revocation=True` of `WrapJWT`, `verify` then raises
`TokenRevokedError` for a revoked token.

```python
myjwt = WrapJWT(
    wrapjwk=myjwk,
    issuer="https://example.com",
    audience="api",
    revocation=True,
)

# the signature is verified, the 'jti' is saved until the token expires
myjwt.revoke_token(token)

# without the token, e.g. from a list of issued tokens of your application
myjwt.revoke_jti(jti, expires_at=exp)
```

- The storage saves the `jti` of a revoked token until its `exp` (plus
  `leeway`). `StorageRedis` deletes the records itself, `StorageFile` and
  `StorageVault` delete them in `prune`, see
  [Delete old keys](./keys.md#delete-old-keys-prune).
- `revoke_token` refuses a token without `exp` (`TokenClaimError`), an
  expired token is not saved.
- `verify` reads the storage once more for each token. A storage failure
  raises `KeysLoadError` (HTTP 500), never accept the token then.
- All processes which verify tokens must have `revocation=True` and the same
  storage, a process without it accepts a revoked token. Services with
  `StorageJWKS` cannot check revoked tokens.
- Tokens created by versions older than 0.4.0 have no `jti` and cannot be
  revoked. `require_jti=True` of `WrapJWT` makes them invalid.
- The storage of the keys saves also the revoked tokens, no other storage
  is needed. Supported by `StorageRedis`, `StorageVault` and `StorageFile`.
  With `StorageVault` each `verify` sends one more request to Vault, for a
  high traffic `StorageRedis` is faster. `StorageFile` works only on one
  server.
- A custom storage needs the methods listed in
  [Custom storage](./storage.md#custom-storage), otherwise `WrapJWT` raises
  `ConfigurationError`.

All tokens of a key are revoked by revoking the key, see
[Revoke keys](./keys.md#revoke-keys).

## Exceptions

All exceptions of this library are subclasses of `WrapperErrors`:

- `InvalidTokenError` and its subclasses - invalid token (HTTP 401), see
  [Verify token](#verify-token)
- `KeysLoadError`, `KeysSaveError` - storage errors (file system, Vault,
  Redis, an unavailable JWKS), the original exception is available as
  `__cause__`
- `KeysNotFoundError` - subclass of `KeysLoadError`, the keys are not in
  the storage (`verify` raises `TokenKidUnknownError` instead)
- `KeysNotLoadedError` - `WrapJWK` getters called before `load_keys` or
  `generate_keys`
- `GenerateKeysError` - key generation failed
- `CreateTokenException` - missing or invalid claims or `exp`
- `ConfigurationError` - invalid parameters of `WrapJWT`, `verify` without
  `issuer` and `audience`, or `revocation=True` with a storage which does
  not support it
- `ObjectTypeError` - invalid object passed to a constructor

Source of the exceptions and of the storage errors in `__cause__`:

- [hvac exceptions](https://hvac.readthedocs.io/en/stable/source/hvac_exceptions.html)
- [redis-py exceptions](https://redis.readthedocs.io/en/stable/exceptions.html)
- [joserfc_wrapper exceptions](./api.md#exceptions)

[< Previous: Tokens](./tokens.md) |
[Contents](./index.md) |
[Next: Verifying services (JWKS) >](./jwks.md)
