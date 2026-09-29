# Signature keys

## Create new signature keys

At least one key must exist in the storage before the first token is
created. The new keys become the last keys, which sign new tokens.

```python
myjwk = WrapJWK(storage=storage)

# create the first keys, or rotate the existing keys
myjwk.rotate()
```

The keys are EC P-256 for signing (ES256) and oct 128 bits for encrypted
data (JWE). The same with the CLI: `genjw keys`.

## Lifecycle of a key

1. **Last:** the key signs new tokens.
2. **Retired:** after a rotation the key stops signing new tokens. Tokens
   signed by it stay valid until they expire.
3. **Revoked** (optional): all tokens signed by the key are invalid
   immediately.
4. **Deleted** by `prune`, when no valid token signed by it can exist.

`myjwk.list_keys()` (or `genjw list`) shows all keys with their creation,
retirement and revocation times.

## Key rotation

Rotate the keys by age: set `max_key_age` (seconds) of `WrapJWT`, `create`
generates new keys when the last keys are older.

```python
myjwt = WrapJWT(
    wrapjwk=myjwk,
    issuer="https://example.com",
    audience="api",
    default_exp=3600,
    max_key_age=30 * 86400,  # new keys every 30 days
    max_token_lifetime=86400,  # no token longer than 1 day, see prune
)
```

- Rotation never deletes keys: tokens signed by the retired keys stay valid
  until their `exp`.
- Keys can be rotated manually: `myjwk.rotate()` or `genjw rotate`.
- Concurrent processes rotate the keys only once, see
  [Storages](./storage.md#concurrent-processes).
- Keys created by versions older than 0.5.0 have no creation time, they are
  rotated once when `max_key_age` is set.

The `payload` parameter of `create` (rotation after a number of signed
tokens) is deprecated since 0.5.0 and will be removed in 1.0.0, use
`max_key_age`.

## Revoke keys

When a key is leaked or compromised, revoke it. All tokens signed by it
become invalid, `verify` raises `TokenKeyRevokedError`.

```python
myjwk.revoke(kid)
```

When the revoked key is the last key, new keys are generated first, so
creating tokens continues. The revoked key stays in the storage (with the
time of revocation) until `prune` deletes it. With the CLI:
`genjw revoke --kid=<kid> --yes` (without `--yes` it only shows what would
happen).

A single token cannot be revoked yet, only all tokens of a key.

## Delete old keys (prune)

`prune` deletes the keys which cannot sign any valid token anymore: keys
retired longer than the longest lifetime of a token (`max_token_lifetime`
of `WrapJWT`). `create` refuses a token with a longer `exp`, so all tokens
of such keys have expired.

```python
deleted = myjwt.prune()  # Key IDs of the deleted keys
```

- Run it from the application or from cron (`genjw prune --lifetime="days=1"`),
  it never runs automatically.
- The last key is never deleted. Revoked keys are deleted by the same rule.
- Keys created by versions older than 0.5.0 have no retirement time and are
  never deleted automatically.
- The storage must support listing keys, `StorageVault` needs the `list`
  capability, see [Storages](./storage.md#vault-policy).
- Encrypted data (JWE) of a deleted key cannot be decrypted anymore, use JWE
  only for data inside tokens, see [Encrypted data](./jwe.md).

[< Previous: Storages](./storage.md) |
[Contents](./index.md) |
[Next: Tokens >](./tokens.md)
