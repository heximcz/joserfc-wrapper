# Tokens

How tokens look like and how to create them.

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
    "sub": "123",  # subject (e.g. user ID), str, required in 1.0.0
    "jti": "5b0be60b1c91438e9f5c0a6c1b2d3e4f",  # unique token ID, automatic
    "iat": 1705418960,  # created automatically
    "exp": 1705422560,  # expiration, required by verify
}
```

Other claims are added to the token unchanged.

`sub` (the subject of the token, e.g. a user ID) is the standard claim of
RFC 7519 and a required claim of access tokens (RFC 9068). It is a string,
`create` without it raises `DeprecationWarning` and `sub` will be required
by `create` and `verify` in 1.0.0. `uid` is optional since 0.8.0 (an int when
present), move to `sub`.

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
    max_key_age=30 * 86400,  # optional: rotate the keys every 30 days
    max_token_lifetime=86400,  # optional: longest exp, required by prune
    revocation=False,  # optional: verify checks revoked tokens
    require_jti=False,  # optional: with revocation, a token without jti fails
    token_type=None,  # optional: the kind of tokens, e.g. "at+jwt"
)
```

See [Signature keys](./keys.md) for `max_key_age` and `max_token_lifetime`,
[Revoke tokens](./verify.md#revoke-tokens) for `revocation` and
`require_jti`, [Token types](#token-types) for `token_type`.

## Token types

An application often creates more kinds of tokens with the same keys, for
example access tokens for an API (15 minutes), refresh tokens (30 days) or
tokens in a link of an e-mail (reset of a password). Without a check a
token of one kind can be used as another one: a refresh token or a token
from an e-mail sent to the API as an access token has a valid signature and
`exp` and passes (cross-JWT confusion, RFC 8725). `aud` separates services,
not kinds of tokens for the same service.

Set the kind by `token_type`, `create` writes it to the `typ` header and
`verify` rejects tokens of other kinds (`TokenTypeError`):

```python
access = WrapJWT(myjwk, issuer=ISS, audience="api", token_type="at+jwt")
refresh = WrapJWT(myjwk, issuer=ISS, audience="api", token_type="refresh+jwt")

token = refresh.create({"sub": "123"}, exp=30 * 86400)
access.verify(token)  # raises TokenTypeError
```

- `at+jwt` is the type of OAuth 2.0 access tokens (RFC 9068), use your own
  types like `refresh+jwt` or `reset+jwt` for other kinds.
- The type is compared case-insensitively, the prefix `application/` is
  optional.
- Without `token_type` tokens have `typ: JWT` and `verify` does not check
  the type (the behavior of older versions). Set `token_type` in all
  services which create and verify the tokens.
- With one kind of tokens it is optional, set it when you add a second one.

## Create token

```python
try:
    # a new token is always signed by the last keys in the storage,
    # 'iss' and 'aud' are added from WrapJWT, 'jti' is added automatically
    token = myjwt.create(claims={"sub": "123"})
    print(f"Token: {token[:20]}..., Length: {len(token)} bytes")
except Exception as e:
    print(f"{type(e).__name__}: {e}")
```

- `exp` (seconds) overrides `default_exp`: `myjwt.create(claims, exp=600)`.
  The `exp` claim can be also set directly in claims, but not both.
- A token without `exp` is invalid for `verify`, create tokens with `exp`
  or set `default_exp`.
- `iss` or `aud` in claims must match `issuer` and `audience` of WrapJWT,
  otherwise `CreateTokenError`.
- `sub` must be a non-empty string, `uid` an int, otherwise
  `CreateTokenError`.
- `jti` (unique token ID) is added when it is not in the claims, a custom
  `jti` must be a non-empty string. `myjwt.get_jti(token)` returns it after
  verifying the signature, for example for logging.

[< Previous: Signature keys](./keys.md) |
[Contents](./index.md) |
[Next: Verifying tokens >](./verify.md)
