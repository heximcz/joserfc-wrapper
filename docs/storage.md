# Storages

Where the signature keys are saved.

## Storage configuration

All processes and services which create or verify tokens share the same
storage with the signing keys.

```python
# file storage, the directory must exist
storage = StorageFile(cert_dir="/etc/myapp/keys")

# HashiCorp Vault storage, KV v2 secrets engine (default)
storage = StorageVault(
    url="<vault url>",
    token="<token>",
    mount="<secure mount>",
)

# KV v1 secrets engine (keys saved by versions older than 0.3.0),
# not safe for concurrent processes, deprecated: removed in 1.0.0
storage = StorageVault(
    url="<vault url>",
    token="<token>",
    mount="<secure mount>",
    kv_version=1,
)

# Redis storage (pip install joserfc-wrapper[redis])
storage = StorageRedis.from_url("redis://:<password>@redis.example:6379/0")

# only public keys from a JWKS, for services which only verify tokens
storage = StorageJWKS("https://auth.example.com/.well-known/jwks.json")
```

Create the storage object once and share it in the application (all
threads), it keeps the cache of the verification keys. `StorageJWKS` is
described in [Verifying services (JWKS)](./jwks.md).

`StorageFile` saves each key to `<kid>.json` and the last Key ID to
`last-key-id.json`, both readable only by the owner (`0600`). Writes are
atomic and locked by the `.lock` file in the same directory. Revoked tokens
are saved to the `revoked/` subdirectory, `StorageVault` saves them to
`<mount>/revoked/`.

A KV v2 mount for `StorageVault` can be created by:

```bash
vault secrets enable -path=jwt -version=2 kv
```

## Vault policy

The Vault token of the application needs a policy for the mount with the
keys. The examples use the KV v2 mount `jwt`, replace it by your mount.

What each feature needs (checked by the Vault audit log):

| Feature | Operations |
| --- | --- |
| `verify`, `decode`, `WrapJWE.decrypt` | `read` on `jwt/data/*` |
| `create`, `rotate`, `revoke` | `create`, `read`, `update` on `jwt/data/*` |
| concurrent rotation (cleanup of unused keys) | `delete` on `jwt/metadata/*` |
| `list_keys`, `prune` | `list` on `jwt/metadata/*` |
| `prune` | `delete` on `jwt/metadata/*` |
| `verify` with token revocation | `read` on `jwt/data/*` |
| `revoke_token`, `revoke_jti` | `create`, `update` on `jwt/data/*` |
| `jwks`, `genjw jwks` | `list` on `jwt/metadata/*`, `read` on `jwt/data/*` |

An application which creates and verifies tokens and manages the keys:

```text
# keys, counter of tokens, metadata and the last Key ID
path "jwt/data/*" {
  capabilities = ["create", "read", "update"]
}

# list_keys and prune (list), prune and cleanup after a concurrent
# rotation (delete)
path "jwt/metadata/*" {
  capabilities = ["list", "delete"]
}

# renew the own periodic token of the application
path "auth/token/renew-self" {
  capabilities = ["update"]
}
```

A service which only verifies tokens:

```text
path "jwt/data/*" {
  capabilities = ["read"]
}
```

The records contain also the private keys, so a service with `read` can
create tokens. Services which only verify tokens should use the JWKS and no
access to Vault, see [Verifying services (JWKS)](./jwks.md).

`auth/token/renew-self` is needed only when the application renews its own
periodic token. KV v1 (`kv_version=1`) has no `data/` and `metadata/`
paths, use `jwt/*` with the capabilities of both paths.

KV v1 is deprecated since 0.5.0 (`DeprecationWarning`) and its support will
be removed in 1.0.0. Move the keys to a KV v2 mount: copy the records
`<kid>` and `last-key-id` to the new mount, or create new keys there
(`rotate`) and keep the KV v1 mount until the old tokens expire.

## Redis

`StorageRedis` needs Redis 6.2 or newer and the optional dependency
redis-py 5 or newer:

```bash
pip install "joserfc-wrapper[redis]"
```

Create it from a URL or from a configured redis-py client, all options of
redis-py are available (TLS, timeouts, Sentinel, ...):

```python
from joserfc_wrapper import StorageRedis

# redis://, rediss:// (TLS) or unix:// URL, other options of redis.Redis
storage = StorageRedis.from_url(
    "rediss://app:<password>@redis.example:6380/0",
    prefix="myapp:jwt:",
    socket_timeout=5,
)

# or your own client
import redis

client = redis.Redis(host="redis.example", port=6379, password="...")
storage = StorageRedis(client, prefix="myapp:jwt:")
```

- Keys: `<prefix><kid>` with the key record (JSON), `<prefix>last-key-id`
  and `<prefix>revoked:<sha256 of jti>` for revoked tokens. The default
  prefix is `jwt:`, use your own prefix in a shared Redis.
- The key records are changed by Lua scripts, safe for concurrent processes.
- **Persistence:** Redis must save the data (AOF or RDB snapshots). Without
  persistence the keys are lost after a restart of Redis and all tokens
  become invalid. Do not use a Redis with an eviction policy
  (`maxmemory-policy` other than `noeviction`) for the keys.
- **Redis Cluster:** all keys must be in one hash slot, use a prefix with a
  hash tag, for example `prefix="{jwt}:"`.
- Records of revoked tokens expire in Redis automatically.

An ACL user for the application (replace `jwt:` by your prefix,
`ACL SETUSER` adds the rules):

```bash
redis-cli ACL SETUSER app on ">password" "~jwt:*"
redis-cli ACL SETUSER app +get +set +exists +del +scan +multi +exec
redis-cli ACL SETUSER app +evalsha "+script|load"
```

`+evalsha` and `+script|load` run the Lua scripts, `+scan` and `+del` are
needed only by `list_keys` and `prune`.

## Concurrent processes

More processes can sign tokens with the same storage. The keys are rotated
only once (by age, revocation or the deprecated `payload`) and the counter of
tokens is increased atomically:

- `StorageFile` locks writes with `fcntl.flock` on the `.lock` file in
  `cert_dir` (not on Windows, not reliable on NFS).
- `StorageVault` with KV v2 uses check-and-set. KV v1 is not atomic.
- `StorageRedis` uses Lua scripts, Redis runs each script atomically.
- A custom storage is atomic only when it overrides `increase_counter`,
  `replace_last_keys` and `update_metadata`, see below.

One storage object, `WrapJWK` and `WrapJWT` can be shared by all threads of
the application (since 0.8.0), see [Security notes](./security.md).

## Cache of verification keys

`verify` needs only the public key of a token. The storage object keeps the
public keys (and the time of revocation) in memory for `key_cache_ttl`
seconds (default 300), so verifying tokens does not read the storage for
each request.

```python
# default: 300 seconds
storage = StorageVault(url, token, mount, key_cache_ttl=60)
# no cache, every verify reads the storage
storage = StorageFile(cert_dir="/etc/myapp/keys", key_cache_ttl=0)
```

- The cache belongs to the storage object, share one object in the
  application.
- A revoked key is rejected at once in the process which revoked it. Other
  processes reject it after `key_cache_ttl` at the latest.
- New keys after a rotation are not delayed, an unknown `kid` is always
  read from the storage.
- The revocation of single tokens (`revocation=True`) is not cached, it is
  checked in the storage for each token.
- `create` is not cached, it reads and writes the storage.
- `storage.clear_key_cache()` forgets the cached keys, e.g. after changing
  the keys by other tools.

## Custom storage

A custom storage, for example a database, must be a subclass of
[`AbstractKeyStorage`](../joserfc_wrapper/abstract_key_storage.py)
and implement:

- `get_last_kid()` - the last Key ID
- `load_keys(kid="")` - returns `(kid, {"data": keys})`, the last keys for
  an empty `kid`
- `save_keys(kid, keys)` - saves the keys and sets them as the last keys
- `save_last_kid(kid)` - sets the last Key ID (since 0.8.0, storages for
  older versions implement `_save_last_id(kid)`, it still works and is
  deprecated)

The keys have this format:

```python
{
    "keys": {"private": dict, "public": dict, "secret": dict},
    "counter": int,
    # metadata since 0.5.0, unix timestamps, keep all fields of the record
    "created": int,
    "retired": int,  # optional
    "revoked": int,  # optional
}
```

For concurrent processes override also `increase_counter(kid, limit)`,
`replace_last_keys(last_kid, kid, keys)` and `update_metadata(kid, fields)`
with atomic implementations. The default implementations use the methods
above and are not atomic.

For `list_keys` and `prune` implement also `list_kids()` and
`delete_keys(kid)`. Without them the storage works, only listing and
deleting keys raise `KeysLoadError` or `KeysSaveError`.

The cache of verification keys and `jwks()` work for custom storages without
any change, they use `load_keys` and `list_kids`. Set `key_cache_ttl` as an
attribute (`self.key_cache_ttl = 60`) to change the lifetime.

For token revocation implement `revoke_jti(jti, expires_at)`,
`is_jti_revoked(jti)` and `prune_revoked(now)`. Without them
`WrapJWT(revocation=True)` raises `ConfigurationError`.

### Testing a custom storage

`joserfc_wrapper.testing` checks that a storage keeps the contract of
`AbstractKeyStorage`: saving and loading keys, verification keys and their
cache, the counter, metadata, rotation, concurrent writes, and listing,
deleting, JWKS and token revocation when the storage implements them. The
checks are plain functions with `assert`, they work with any test framework:

```python
from joserfc_wrapper.testing import check_storage


def test_my_storage():
    # a test storage, the checks create keys and change the last Key ID
    check_storage(MyStorage(...))
    # a storage without atomic methods
    check_storage(MySimpleStorage(...), atomic=False)
```

`check_read_only_storage(storage, kid)` checks a storage which only verifies
tokens (like `StorageJWKS`).

[< Previous: Getting started](./getting-started.md) |
[Contents](./index.md) |
[Next: Signature keys >](./keys.md)
