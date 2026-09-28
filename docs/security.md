# Security notes for developers

What to watch out for when you use `joserfc-wrapper` to protect an API.
Valid for version 0.3.1.

## 1. `decode` is not enough, always call `validate`

`decode` verifies only the signature. It does not check the expiration,
the issuer or the audience. A correctly signed token for another
application, or an expired token, passes `decode`.

```python
# WRONG: an expired token or a token for another audience is accepted
token = myjwt.decode(raw)

# RIGHT: signature and claims
token = myjwt.decode(raw)
if not myjwt.validate(token, {"iss": "https://example.com", "aud": "api"}):
    raise Unauthorized()
```

Always check the return value of `validate`, it returns `False`, it does not
raise an exception for an invalid token.

## 2. `validate` checks only what you pass

`validate` compares only the claims in its argument. `exp` and `nbf` are
checked only when the token contains them.

- `validate(token, {})` returns `True` for any correctly signed token
  without `exp`. Always pass at least `iss` and `aud`.
- A token without `exp` is valid as long as its signing key exists. Require
  it in your application:

```python
if "exp" not in token.claims:
    raise Unauthorized()
```

- Create tokens with an expiration: `myjwt.create(claims, exp=3600)` or
  `genjw token --exp="hours=1"`.

## 3. Claims are readable by anyone

A JWT is signed, not encrypted. Anyone who has the token can read its claims
without any key. Do not put passwords, personal data or other secrets into
claims. Encrypt them by `WrapJWE`, see [Create token with encrypted
data](./index.md#create-token-with-encrypted-data).

## 4. Access to the storage means the ability to sign tokens

The storage contains the private keys. Whoever can read it can create valid
tokens for any user.

- `StorageFile` saves keys with `0600` permissions. Keep `cert_dir` readable
  only by the application user and do not put it into a backup or a Docker
  image available to others.
- Vault: give the application token only the paths it needs (`<mount>/data/*`
  and `<mount>/metadata/*` for rotation), never `sys/*`.
- A service which only verifies tokens also needs read access to the keys
  (including the private key) in this version.

## 5. Tokens cannot be revoked one by one

A token is valid until it expires. There is no list of revoked tokens.

- Use a short `exp` for API tokens.
- `payload` limits the number of tokens signed by one key, so a leaked key
  affects only a limited number of tokens.
- A leaked key: generate new keys (`genjw keys`) and delete the leaked key
  from the storage. All tokens signed by it become invalid.

## 6. Encrypted data depend on the keys

`WrapJWE` encrypts data by the secret key stored together with the signing
key. When the key is deleted from the storage, the data encrypted by it
cannot be decrypted anymore. Use JWE for data inside tokens with a limited
lifetime, not for long-term storage.

## 7. Clock synchronisation

`exp` and `nbf` are checked without any tolerance. A token which expired
one second ago is invalid. Keep the clocks of all servers which create and
verify tokens synchronised (NTP).

## 8. Storage errors are not invalid tokens

Distinguish a failure of the storage from an invalid token, otherwise an
unavailable Vault looks like an attack or all clients get `401`.

```python
from hvac.exceptions import Forbidden, VaultDown
from requests.exceptions import RequestException
from joserfc_wrapper import KeysLoadError

# Vault errors and connection errors, not errors of the token
SERVER_ERRORS = (Forbidden, VaultDown, RequestException)

try:
    token = myjwt.decode(raw)
except KeysLoadError as e:
    if isinstance(e.__cause__, SERVER_ERRORS):
        raise ServerError()  # 500: storage or application token problem
    raise Unauthorized()  # 401: unknown kid
```

Do not return exception messages to clients, log them.

## 9. Do not log tokens

A token is a credential. Log the `kid`, the claims or the reason of the
failure, never the whole token.

## 10. Concurrency and threads

- `StorageFile` locks writes by `fcntl.flock`. It does not work on Windows
  and it is not reliable on NFS.
- `StorageVault` with KV v1 is not safe for concurrent processes, use KV v2.
- A custom storage is safe for concurrent processes only when it overrides
  `increase_counter` and `replace_last_keys` with atomic implementations.
- `WrapJWK` and `WrapJWT` keep state (the loaded key, the last `kid`).
  Create new instances for each thread or request, do not share them.

## 11. Vault KV v2 settings

- Keep `delete_version_after` of the mount disabled (`0s`). When enabled,
  Vault deletes old keys and tokens signed by them become invalid.
- The default lease TTL of the mount does not affect the keys, KV data have
  no lease.
- `max_versions` limits only the history of each key record (the counter is
  written for every token), the current version is never deleted.

[< back to index](./index.md)
