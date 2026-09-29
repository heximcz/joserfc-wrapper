# Standards (RFC)

How the library follows the standards of JWT. The behavior was checked in
0.9.0 with forged tokens, the tests are in `tests/test_standards.py`.

## Algorithms

- **RFC 7518 (JWA), RFC 9864:** Tokens are signed only by ES256 (ECDSA P-256
  SHA-256), a fully specified algorithm. `verify` accepts no other algorithm.
- **RFC 8725 3.1, 3.2:** `alg: none`, HS256 with the public key as a secret (key
  confusion) and other algorithms in the header are rejected.
- **RFC 7516, RFC 8725 3.1:** `WrapJWE.decrypt` accepts only A128KW + A128GCM
  (since 0.9.0), the algorithms of `WrapJWE.encrypt`.
- **RFC 8725 3.6, 8725bis:** `WrapJWE` does not compress data. Other compressed
  data are rejected, `joserfc` limits the decompressed size to 256 kB.

## Header

- **RFC 7515 4.1.11:** Tokens with unknown `crit` parameters (e.g. `b64: false`,
  RFC 7797) are rejected.
- **RFC 8725 3.10, 8725bis:** The key is selected only by `kid` from your
  storage. `jwk`, `jku`, `x5u` and `x5c` in the header are ignored. `kid` is
  validated strictly: `uuid4().hex`, or a RFC 7638 thumbprint (keys of 1.0.0).
- **RFC 8725 2.8, 3.11, 3.12:** Explicit typing: `WrapJWT(token_type="at+jwt")`
  writes the `typ` header and `verify` rejects other types (`TokenTypeError`),
  see [Token types](./tokens.md#token-types). Without `token_type` the header is
  `typ: JWT` and it is not checked.
- **RFC 7515 4.1.9:** `typ` is compared case-insensitively, `application/` is
  optional.
- **RFC 8725 3.3, 8725bis:** Nested tokens (`cty: JWT`) are not processed, only
  the outer token is verified.

## Claims

- **RFC 7519 4.1.4:** `exp` is required by `verify` (stricter than the RFC). A
  NumericDate may be a non-integer number.
- **RFC 7519 4.1.5, 4.1.6:** `nbf` and `iat` are checked with `leeway`, a token
  issued in the future is rejected. Claims with wrong types (e.g. `exp` as a
  string) are rejected.
- **RFC 7519 4.1.1, RFC 8725 3.8:** `iss` is required by `verify` and compared
  exactly (case-sensitive).
- **RFC 7519 4.1.3, RFC 8725 3.9:** `aud` is required by `verify`, a list must
  contain an allowed value.
- **RFC 7519 4.1.2:** `sub` must be a string. It is optional in 0.x and will be
  required by `create` and `verify` in 1.0.0.
- **RFC 7519 4.1.7:** `jti` is always added (`uuid4().hex`), revoked tokens are
  identified by it.
- **RFC 7519 7.2:** The payload must be a JSON object, otherwise
  `TokenDecodeError`.
- **RFC 7519 4:** Duplicate claim names: the last value is used (the RFC allows
  it). Only the issuer can create such a token, it must be correctly signed.

## Keys

- **RFC 7517:** Keys are stored as JWK, `WrapJWK.jwks()` publishes a JWK Set
  with `kid`, `kty`, `crv`, `x`, `y`, `use: sig` and `alg: ES256`, never private
  keys.
- **RFC 7638:** `kid` is `uuid4().hex` in 0.x. Keys created by 1.0.0 will use
  the JWK thumbprint, 0.9.0 already accepts both.

## Access tokens (RFC 9068)

RFC 9068 is an optional profile of JWT access tokens of OAuth 2.0, the
library is not an OAuth server and does not need it. A JWT access token of
the profile needs `typ: at+jwt` and the claims `iss`, `exp`, `aud`, `sub`,
`client_id`, `iat` and `jti`. The library adds `iss`, `aud`, `exp`, `iat`
and `jti`, the rest is up to you:

```python
myjwt = WrapJWT(
    wrapjwk=myjwk,
    issuer="https://auth.example.com",
    audience="api",
    default_exp=900,
    token_type="at+jwt",
)
token = myjwt.create({"sub": "123", "client_id": "web-app"})
```

`verify` with `token_type="at+jwt"` checks the token as the profile requires
(`typ`, `iss`, `aud`, `exp`, the signature). The profile requires servers to
support also RS256, the library supports only ES256: a service built only
on the library cannot accept RS256 tokens of other issuers. `sub` will be
required in 1.0.0.

## Things to know

- **ECDSA signatures are malleable.** A signature `(r, s)` is also valid as
  `(r, n - s)`, so the same token can exist in two different strings. JOSE
  does not forbid it. Never identify a token by its string or its hash, use
  `jti` (as the revocation of tokens does).
- **Stricter than the RFC:** `verify` requires `exp`, `iss` and `aud`.
- **Not supported:** other algorithms (RSA, EdDSA), JWS JSON serialization,
  nested tokens, JWKS of other issuers.

[< Previous: Security notes for developers](./security.md) |
[Contents](./index.md) |
[Next: CLI >](./cli.md)
