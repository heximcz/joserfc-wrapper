# Upgrading

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
