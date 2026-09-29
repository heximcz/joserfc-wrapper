# Signature keys

## Create new signature keys

At least one key must exist in the storage before the first token is
created. The new keys become the last keys, which sign new tokens.

```python
myjwk = WrapJWK(storage=storage)

# create the first keys, or rotate the existing keys, returns the Key ID
kid = myjwk.rotate()
```

Each key has a signature key and an oct 128 bits key for encrypted data
(JWE). The Key ID (`kid`) is the RFC 7638 thumbprint of the signature key.
The same with the CLI: `genjw keys`.

## Algorithms

| Algorithm | Key | Default |
| --- | --- | --- |
| ES256 | EC P-256 | yes |
| Ed25519 | OKP Ed25519 (RFC 8037, RFC 9864) | no |

```python
myjwk.rotate(algorithm="Ed25519")  # the next keys use Ed25519
```

- The algorithm belongs to the key: a token is signed and verified by the
  algorithm of its key, never by the `alg` header of a token. The keys of
  both algorithms can be in the storage at the same time.
- A change of the algorithm is a rotation: the old keys verify their tokens
  until they expire.
- For the automatic rotation set `key_algorithm` of `WrapJWT`, see below.
- RS256 (RSA) is not supported and will never be supported.

## Lifecycle of a key

1. **Last:** the key signs new tokens.
2. **Retired:** after a rotation the key stops signing new tokens. Tokens
   signed by it stay valid until they expire.
3. **Revoked** (optional): all tokens signed by the key become invalid
   (in other processes after the cache of verification keys expires, see
   [Revoke keys](#revoke-keys)).
4. **Deleted** by `prune`, when no valid token signed by it can exist.

`myjwk.list_keys()` (or `genjw list`) shows all keys with their algorithm
and their creation, retirement and revocation times.

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
    key_algorithm="ES256",  # the algorithm of new keys, or "Ed25519"
)
```

- Rotation never deletes keys: tokens signed by the retired keys stay valid
  until their `exp`.
- Keys can be rotated manually: `myjwk.rotate()` or `genjw rotate`.
- Concurrent processes rotate the keys only once, see
  [Storages](./storage.md#concurrent-processes).
- Keys created by versions older than 0.5.0 have no creation time, they are
  rotated once when `max_key_age` is set.

## Revoke keys

When a key is leaked or compromised, revoke it. All tokens signed by it
become invalid, `verify` raises `TokenKeyRevokedError`.

```python
myjwk.revoke(kid)
```

Tokens of the revoked key are rejected at once by the same storage object.
Other storage objects (other processes) reject them after `key_cache_ttl`
(default 300 seconds) at the latest, see [Cache of verification keys](./storage.md#cache-of-verification-keys),
services with the JWKS after its next download, see
[Verifying services (JWKS)](./jwks.md).

When the revoked key is the last key, new keys are generated first (with the
algorithm of the revoked key, or `myjwk.revoke(kid, algorithm="Ed25519")`),
so creating tokens continues. The revoked key stays in the storage (with the
time of revocation) until `prune` deletes it. With the CLI:
`genjw revoke --kid=<kid> --yes` (without `--yes` it only shows what would
happen).

A single token is revoked by `revoke_token`, see
[Revoke tokens](./verify.md#revoke-tokens).

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
- Records of revoked tokens (`revoke_token`) which expired are deleted too.
- Keys retired by versions older than 0.5.0 have no creation and retirement
  time and are never deleted automatically, delete them by
  `storage.delete_keys(kid)` when their tokens have expired. The last key of
  such a version gets the retirement time by the next rotation and is
  deleted normally.
- Keys which are not the last keys and were never retired (e.g. two
  processes created the first keys at the same time) are retired by `prune`
  and deleted by a later `prune`.
- The storage must support listing keys, `StorageVault` needs the `list`
  capability, see [Storages](./storage.md#vault-policy).
- Encrypted data (JWE) of a deleted key cannot be decrypted anymore, use JWE
  only for data inside tokens, see [Encrypted data](./jwe.md).

[< Previous: Storages](./storage.md) |
[Contents](./index.md) |
[Next: Tokens >](./tokens.md)
