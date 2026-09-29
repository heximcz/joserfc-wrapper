# Storages

Where the signature keys are saved.

## Storage configuration

All processes and services which create or verify tokens share the same
storage with the signing keys.

```python
# file storage, the directory must exist
storage = StorageFile(cert_dir="/etc/myapp/keys")

# HashiCorp Vault storage (pip install joserfc-wrapper[vault]), the KV v2
# secrets engine
storage = StorageVault(
    url="<vault url>",
    token="<token>",
    mount="<secure mount>",
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

`StorageVault` needs the Vault client `hvac`, install it by
`pip install "joserfc-wrapper[vault]"`. It supports only the KV v2 secrets
engine, KV v1 is not supported.

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
# keys, metadata and the last Key ID
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
periodic token. `create` writes to Vault only when it rotates the keys
(`max_key_age`, revoked keys).

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
- **Redis Cluster:** use `redis.RedisCluster` and a prefix with a hash
  tag, for example `prefix="{jwt}:"`, all keys must be in one hash slot
  (one node). A cluster client without a hash tag raises `ValueError`.
  Tested with Redis 7 and redis-py 5 and newer. The CLI (`REDIS_URL`)
  supports only a single Redis.
- Records of revoked tokens expire in Redis automatically.

```python
import redis

client = redis.RedisCluster.from_url("redis://redis-1.example:6379")
storage = StorageRedis(client, prefix="{myapp:jwt}:")
```

An ACL user for the application (replace `jwt:` by your prefix,
`ACL SETUSER` adds the rules):

```bash
redis-cli ACL SETUSER app on ">password" "~jwt:*"
redis-cli ACL SETUSER app +get +set +exists +del +scan
redis-cli ACL SETUSER app +evalsha "+script|load"
```

`+evalsha` and `+script|load` run the Lua scripts, `+scan` and `+del` are
needed only by `list_keys` and `prune`.

## Concurrent processes

More processes can sign tokens with the same storage. The keys are rotated
only once (by age or revocation) and the metadata are changed atomically:

- `StorageFile` locks writes with `fcntl.flock` on the `.lock` file in
  `cert_dir` (not on Windows, not reliable on NFS).
- `StorageVault` uses check-and-set of KV v2.
- `StorageRedis` uses Lua scripts, Redis runs each script atomically.
- A custom storage must implement `replace_last_keys` and
  `update_metadata` atomically, see below.

`create` does not write to the storage, only a rotation does. One storage
object, `WrapJWK`, `WrapJWT` and `WrapJWE` can be shared by all threads of
the application, see [Security notes](./security.md).

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
- A revoked key is rejected at once by the storage object which revoked it.
  Other storage objects (other processes) reject it after `key_cache_ttl`
  at the latest.
- New keys after a rotation are not delayed, an unknown `kid` is always
  read from the storage.
- The revocation of single tokens (`revocation=True`) is not cached, it is
  checked in the storage for each token.
- `create` does not use the cache, it reads the last keys from the storage
  and writes to it only when it rotates the keys.
- `storage.clear_key_cache()` forgets the cached keys, e.g. after changing
  the keys by other tools.

## Custom storage

A custom storage, for example a database, must be a subclass of
[`AbstractKeyStorage`](../joserfc_wrapper/abstract_key_storage.py)
and implement:

- `get_last_kid()` - the last Key ID
- `load_keys(kid="")` - returns `(kid, {"data": record})`, the last keys for
  an empty `kid`
- `save_keys(kid, record)` - saves the keys and sets them as the last keys
- `save_last_kid(kid)` - sets the last Key ID
- `replace_last_keys(last_kid, kid, record)` - atomically saves new keys as
  the last keys only when the last Key ID is still `last_kid` (a rotation by
  concurrent processes happens only once)
- `update_metadata(kid, fields)` - atomically sets fields of a record and
  keeps all other fields

Use a lock, check-and-set or a transaction for the atomic methods. Set
`not_found_errors` to the exceptions of unknown keys, `verify` then raises
`TokenKidUnknownError` (HTTP 401) instead of `KeysLoadError` (HTTP 500).

A key record:

```python
{
    "keys": {"private": dict, "public": dict, "secret": dict},
    # unix timestamps, keep all fields of the record
    "created": int,
    "retired": int,  # optional, set by a rotation
    "revoked": int,  # optional, set by revoke
}
```

Records of the 0.x versions may have a `counter` and no `created`, they are
loaded as well. The algorithm of a key (ES256, Ed25519) is given by its
public key.

For `list_keys`, `prune` and `jwks` implement also `list_kids()` and
`delete_keys(kid)`. Without them the storage works, only listing and
deleting keys raise `KeysLoadError` or `KeysSaveError`.

The cache of verification keys works for custom storages without any
change, it uses `load_keys`. Set `key_cache_ttl` as an attribute
(`self.key_cache_ttl = 60`) to change the lifetime.

For token revocation implement `revoke_jti(jti, expires_at)`,
`is_jti_revoked(jti)` and `prune_revoked(now)`. Without them
`WrapJWT(revocation=True)` raises `ConfigurationError`.

### Testing a custom storage

`joserfc_wrapper.testing` checks that a storage keeps the contract of
`AbstractKeyStorage`: saving and loading keys, verification keys and their
cache, metadata, rotation, atomic writes of concurrent threads, tokens of
ES256 and Ed25519 keys, and listing, deleting, JWKS and token revocation
when the storage implements them. The
checks are plain functions with `assert`, they work with any test framework:

```python
from joserfc_wrapper.testing import check_storage


def test_my_storage():
    # a test storage, the checks create keys and change the last Key ID
    check_storage(MyStorage(...))
```

`check_read_only_storage(storage, kid)` checks a storage which only verifies
tokens (like `StorageJWKS`).

[< Previous: Getting started](./getting-started.md) |
[Contents](./index.md) |
[Next: Signature keys >](./keys.md)
