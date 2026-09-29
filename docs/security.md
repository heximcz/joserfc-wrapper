# Security notes for developers

What to watch out for when you use `joserfc-wrapper` to protect an API.

## 1. Use `verify`, never `decode` alone

`decode` verifies only the signature. It does not check the expiration,
the issuer or the audience. A correctly signed token for another
application, or an expired token, passes `decode`.

```python
# WRONG: an expired token or a token for another audience is accepted
token = myjwt.decode(raw)

# RIGHT: signature, exp, nbf, iss, aud in one call
myjwt = WrapJWT(myjwk, issuer="https://example.com", audience="api")
token = myjwt.verify(raw)  # raises InvalidTokenError for an invalid token
```

`verify` raises an exception, it never returns an invalid token. It refuses
to work without `issuer` and `audience`, so a token for another service
cannot pass by mistake. `validate` is deprecated since 0.4.0.

## 2. Every token must expire

`verify` rejects a token without `exp`. Create tokens with an expiration:
set `default_exp` of `WrapJWT`, or `myjwt.create(claims, exp=3600)`, or
`genjw token --exp="hours=1"` (required by the CLI).

Use a short `exp` for API tokens, a revoked token is checked only with
`revocation=True` (see 5).

## 3. Claims are readable by anyone

A JWT is signed, not encrypted. Anyone who has the token can read its claims
without any key. Do not put passwords, personal data or other secrets into
claims. Encrypt them by `WrapJWE`, see [Create token with encrypted
data](./jwe.md#create-token-with-encrypted-data).

## 4. Access to the storage means the ability to sign tokens

The storage contains the private keys. Whoever can read it can create valid
tokens for any user.

- `StorageFile` saves keys with `0600` permissions. Keep `cert_dir` readable
  only by the application user and do not put it into a backup or a Docker
  image available to others.
- Vault: give the application token only the paths it needs (`<mount>/data/*`
  and `<mount>/metadata/*` for rotation), never `sys/*`.
- Redis: use a password (or an ACL user limited to the prefix of the keys,
  see [Redis](./storage.md#redis)) and TLS (`rediss://`) outside a trusted
  network. Do not share the Redis with applications which must not sign
  tokens.
- A service which only verifies tokens with access to the storage can read
  also the private keys. Give such services only the JWKS (`StorageJWKS`),
  see [Verifying services (JWKS)](./jwks.md).
- Publish the JWKS only over HTTPS. Whoever can change it on the way can add
  own keys, `StorageJWKS` refuses `http://` by default.

## 5. Revoking tokens

Without `revocation=True` of `WrapJWT` a token is valid until it expires,
only all tokens of a key can be revoked.

- Use a short `exp` for API tokens.
- Revoke a single token (logout, a leaked token) by `revoke_token` with
  `revocation=True`, see [Revoke tokens](./verify.md#revoke-tokens). Every
  service which verifies tokens must enable it, otherwise it accepts the
  revoked token.
- Rotate the keys regularly (`max_key_age`), a leaked key then affects only
  the tokens of a limited period.
- A leaked key: revoke it (`myjwk.revoke(kid)` or
  `genjw revoke --kid=<kid> --yes`). All tokens signed by it become invalid,
  new keys are generated when it was the last key. Other processes reject
  them after `key_cache_ttl` (default 300 seconds) at the latest, services
  with the JWKS after its next download (`ttl`). For an immediate reaction
  restart the services or lower the times.

## 6. Encrypted data depend on the keys

`WrapJWE` encrypts data by the secret key stored together with the signing
key. When the key is deleted from the storage (`prune`), the data encrypted
by it cannot be decrypted anymore. Use JWE for data inside tokens with a
limited lifetime, not for long-term storage.

## 7. Clock synchronisation

`exp` and `nbf` are checked without any tolerance by default. A token which
expired one second ago is invalid. `leeway` of `WrapJWT` sets a tolerance in
seconds. Keep the clocks of all servers which create and
verify tokens synchronised (NTP).

## 8. Storage errors are not invalid tokens

Distinguish a failure of the storage from an invalid token, otherwise an
unavailable Vault looks like an attack or all clients get `401`. `verify`
does it for you:

```python
from joserfc_wrapper import InvalidTokenError, KeysLoadError

try:
    token = myjwt.verify(raw)
except InvalidTokenError:
    raise Unauthorized()  # 401: invalid, expired, unknown kid, ...
except KeysLoadError:
    raise ServerError()  # 500: storage or application token problem
```

Do not return exception messages to clients, log them.

## 9. Do not log tokens

A token is a credential. Log the `kid`, the claims or the reason of the
failure, never the whole token.

## 10. Concurrency and threads

- `StorageFile` locks writes by `fcntl.flock`. It does not work on Windows
  and it is not reliable on NFS.
- `StorageRedis` changes the keys by atomic Lua scripts. Redis must persist
  the data (AOF or RDB), otherwise a restart of Redis deletes the keys.
- `StorageVault` with KV v1 is not safe for concurrent processes and is
  deprecated (removed in 1.0.0), use KV v2.
- A custom storage is safe for concurrent processes only when it overrides
  `increase_counter`, `replace_last_keys` and `update_metadata` with atomic
  implementations.
- Since 0.8.0 one storage object, `WrapJWK`, `WrapJWT` and `WrapJWE` can be
  shared by all threads of the application: `create`, `verify`, `decode`,
  `encrypt` and `decrypt` keep no state. The key management methods of
  `WrapJWK` (`rotate`, `revoke`, `load_keys`, `generate_keys` and the
  getters of the loaded keys) keep the loaded keys, use a separate WrapJWK
  for them (e.g. in a cron job).

## 11. Vault KV v2 settings

- Keep `delete_version_after` of the mount disabled (`0s`). When enabled,
  Vault deletes old keys and tokens signed by them become invalid.
- The default lease TTL of the mount does not affect the keys, KV data have
  no lease.
- `max_versions` limits only the history of each key record (the counter is
  written for every token), the current version is never deleted.

[< Previous: Encrypted data (JWE)](./jwe.md) |
[Contents](./index.md) |
[Next: CLI >](./cli.md)
