# Upgrading

## Preparing for 1.0.0

1.0.0 removes everything deprecated in the 0.x series. The changes are
decided, details may change until the release. Prepare on 0.9.x, it
supports the old and the new behavior.

What changes in 1.0.0:

- Python 3.11 or newer.
- The Vault client `hvac` is installed only with the `vault` extra:
  `pip install "joserfc-wrapper[vault]"`.
- Vault KV v1 (`kv_version=1`, `VAULT_KV_VERSION=1`) is removed and will
  not return.
- `sub` is required by `create`, by `genjw token` (`--sub`) and by `verify`:
  a token without `sub` is invalid.
- Removed: `validate` (use `verify`), `payload` and `--payload` (use
  `max_key_age`), the counter of tokens (`create` does not write to the
  storage anymore), `uid` and `--uid` (use `sub`), the old module names
  (`joserfc_wrapper.WrapJWT`, ...), `CreateTokenException` (use
  `CreateTokenError`), `WrapJWT.get_kid()` (use `token.header["kid"]`),
  `_save_last_id` of custom storages (implement `save_last_kid`).
- New keys get a RFC 7638 thumbprint as `kid`, 0.9.x already accepts it.
- New keys can use Ed25519, ES256 stays the default. RS256 is not and will
  never be supported.

How to prepare:

1. Upgrade all services which create or verify tokens to 0.9.x, before any
   of them uses 1.0.0 (keys of 1.0.0 have a new `kid` format).
2. Run the tests of your application with deprecation warnings as errors,
   they show everything removed in 1.0.0:
   `python -W error::DeprecationWarning -m pytest`.
3. Create tokens with `sub` and wait until the older tokens expire (the
   longest lifetime of your tokens, `max_token_lifetime`).
4. Vault: move the keys from KV v1 to KV v2 (see
   [Vault policy](./storage.md#vault-policy)) and install
   `joserfc-wrapper[vault]`.
5. Custom storages: implement `save_last_kid(kid)`.
6. Check the storage, the environment and a token of your application:

   ```bash
   genjw upgrade-check --token="<token>" --lifetime="days=1"
   ```

   It prints `BLOCKER` (stops working after the upgrade) and `WARNING`
   findings and exits with code 1 when there is a blocker, see
   [Upgrade check](./cli.md#upgrade-check).

## Upgrading from 0.9.0

- New command `genjw upgrade-check`, see
  [Preparing for 1.0.0](#preparing-for-100). No other changes.

## Upgrading from 0.8.x

- The library was checked against the RFCs of JWT, see
  [Standards (RFC)](./standards.md).
- `WrapJWE.decrypt` accepts only A128KW + A128GCM without compression
  (RFC 8725). Data encrypted by `WrapJWE` of any version are decrypted,
  data encrypted by other tools with other algorithms are rejected.
- `verify` raises `TokenDecodeError` for a token whose payload is not a JSON
  object (before an `AttributeError`). `revoke_token` accepts a non-integer
  `exp`.
- New `token_type` of `WrapJWT` and `TokenTypeError` against confusion of
  kinds of tokens, see [Token types](./tokens.md#token-types). Without it
  nothing changes. CLI: `genjw token --token-type`, `genjw check
  --token-type`.
- `kid` in the form of a RFC 7638 thumbprint (keys created by 1.0.0) is
  accepted, new keys still use `uuid4().hex`. Upgrade all services to 0.9.x
  before any service uses 1.0.0.
- `StorageVault` imports `hvac` when it is created. Install
  `joserfc-wrapper[vault]` for Vault, `hvac` will be only in this extra in
  1.0.0.
- `StorageRedis` with `redis.RedisCluster` is tested and needs a prefix with
  a hash tag (`ValueError` without it, before the writes failed).
  `save_keys` works with redis-py 5 in a cluster.
- 0.9.x is the last series with Python 3.10, 1.0.0 needs Python 3.11 or
  newer.

## Upgrading from 0.7.x

- `uid` is not required by `create` anymore. Use the standard claim `sub`
  (a string, e.g. `{"sub": "123"}`). `create` without `sub` raises
  `DeprecationWarning`, `sub` will be required by `create` and `verify` in
  1.0.0. Before upgrading to 1.0.0, create tokens with `sub` and wait until
  the older tokens expire (`max_token_lifetime`). `uid` still must be an int
  when present.
- CLI: `genjw token --sub=<subject>`, `--uid` is optional and deprecated.
- The modules have snake_case names: `joserfc_wrapper.wrap_jwt`,
  `wrap_jwk`, `wrap_jwe`, `storage_file`, `storage_vault`, `storage_redis`,
  `storage_jwks`, `abstract_key_storage`, `exceptions`, `token_header` and
  `cli.gen_jwt`. The old names (`joserfc_wrapper.WrapJWT`, ...) still work
  at runtime with `DeprecationWarning` and will be removed in 1.0.0, type
  checkers do not know them. Import from `joserfc_wrapper`, it does not
  change.
- `CreateTokenException` is renamed to `CreateTokenError`, the old name
  works with `DeprecationWarning` (the same class) until 1.0.0.
- Safe for threads: one `WrapJWK`, `WrapJWT` and `WrapJWE` can be shared by
  all threads. `create`, `decode`, `verify`, `encrypt` and `decrypt` do not
  change the loaded keys of `WrapJWK` anymore: after `create` or
  `WrapJWE.encrypt`, `WrapJWK.get_kid()` does not return the Key ID of the
  new token. Read it from the token (`token.header["kid"]`) or the storage
  (`storage.get_last_kid()`).
- `WrapJWT.get_kid()` is deprecated (removed in 1.0.0), use
  `token.header["kid"]` of the token returned by `verify` or `decode`.
- Custom storages: implement `save_last_kid(kid)` instead of
  `_save_last_id(kid)`. Storages with `_save_last_id` still work, in 1.0.0
  `save_last_kid` will be required.

## Upgrading from 0.6.x

- **Cache of verification keys**, enabled by default: the storage object
  keeps the public keys for `key_cache_ttl` seconds (default 300), `verify`
  does not read the storage for each token. A revoked key is rejected at
  once in the same process, in other processes after `key_cache_ttl` at the
  latest. `key_cache_ttl=0` of the storage keeps the previous behavior. Share
  one storage object in the application, see
  [Cache of verification keys](./storage.md#cache-of-verification-keys).
- `WrapJWT.decode` and `verify` load only the public key, the loaded keys of
  `WrapJWK` do not change anymore (before, `WrapJWK` had the keys of the
  last verified token loaded).
- New JWKS: `WrapJWK.jwks()`, `genjw jwks` and `StorageJWKS` for services
  which only verify tokens, see [Verifying services (JWKS)](./jwks.md).
- Custom storages: new methods `load_verification_key`, `load_jwks` and
  `clear_key_cache` with default implementations, no change is needed.
  `joserfc_wrapper.testing` checks them, new `check_read_only_storage`.
- `requests` is a direct dependency (it was installed with `hvac` before).

## Upgrading from 0.5.x

No backward incompatible changes. New features:

- `StorageRedis`, keys in Redis 6.2+, install
  `pip install "joserfc-wrapper[redis]"`, see [Redis](./storage.md#redis).
- Revocation of single tokens: `revocation=True` and `require_jti` of
  `WrapJWT`, `revoke_token`, `revoke_jti`, new `TokenRevokedError`, see
  [Revoke tokens](./verify.md#revoke-tokens). `prune` also deletes expired
  records of revoked tokens.
- `StorageFile` saves revoked tokens to the `revoked/` subdirectory of
  `cert_dir`, `StorageVault` to `<mount>/revoked/`. `list_keys` ignores them.
- Custom storages: new optional methods `revoke_jti`, `is_jti_revoked`,
  `prune_revoked`. `joserfc_wrapper.testing.check_storage` tests a custom
  storage, see [Testing a custom storage](./storage.md#testing-a-custom-storage).
- CLI: `--storage=redis` (`REDIS_URL`, `REDIS_PREFIX`), `genjw revoke-token`,
  `genjw check` rejects revoked tokens.

## Upgrading from 0.4.x

- KV v1 (`StorageVault(kv_version=1)`, `VAULT_KV_VERSION=1`) is deprecated
  (`DeprecationWarning`), its support will be removed in 1.0.0. Move the
  keys to a KV v2 mount, see [Vault policy](./storage.md#vault-policy).
- `payload` of `create` (and `genjw token --payload`) is deprecated
  (`DeprecationWarning`) and will be removed in 1.0.0, rotate the keys by
  age: `max_key_age` of `WrapJWT` (`--max-key-age`).
- Key records contain metadata `created`, `retired`, `revoked`. Keys saved
  by older versions still load, they have no times: they are rotated once
  when `max_key_age` is set and never deleted by `prune`.
- `genjw keys` rotates the keys: the previous keys are marked retired.
- New `WrapJWK.rotate`, `revoke`, `prune`, `list_keys` and `WrapJWT.prune`,
  `verify` raises `TokenKeyRevokedError` for tokens of a revoked key.
- Vault: `list_keys` and `prune` need the `list` capability on
  `<mount>/metadata/*`, see [Vault policy](./storage.md#vault-policy).
- Custom storages: new optional methods `update_metadata`, `list_kids`,
  `delete_keys`. A custom `save_keys` must keep all fields of the record.

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

[< Previous: CLI](./cli.md) |
[Contents](./index.md) |
[Next: API reference >](./api.md)
