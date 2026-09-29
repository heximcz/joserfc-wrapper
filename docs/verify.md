# Verifying tokens

Verify every token by `verify` before you accept it, see also the
[security notes](./security.md).

## Verify token

`verify` checks everything in one call: the signature (the key is selected
by `kid` in the token header), `exp` (required), `nbf`, `iat`, `iss`, `aud`
and `max_age`. It returns the token or raises an exception with the reason.

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
- [joserfc_wrapper exceptions](./api.md#exceptions)

[< Previous: Tokens](./tokens.md) |
[Contents](./index.md) |
[Next: Encrypted data (JWE) >](./jwe.md)
