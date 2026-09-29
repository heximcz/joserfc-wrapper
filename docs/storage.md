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
```

`StorageFile` saves each key to `<kid>.json` and the last Key ID to
`last-key-id.json`, both readable only by the owner (`0600`). Writes are
atomic and locked by the `.lock` file in the same directory.

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

`auth/token/renew-self` is needed only when the application renews its own
periodic token. KV v1 (`kv_version=1`) has no `data/` and `metadata/`
paths, use `jwt/*` with the capabilities of both paths.

KV v1 is deprecated since 0.5.0 (`DeprecationWarning`) and its support will
be removed in 1.0.0. Move the keys to a KV v2 mount: copy the records
`<kid>` and `last-key-id` to the new mount, or create new keys there
(`rotate`) and keep the KV v1 mount until the old tokens expire.

## Concurrent processes

More processes can sign tokens with the same storage. The keys are rotated
only once (by age, revocation or the deprecated `payload`) and the counter of
tokens is increased atomically:

- `StorageFile` locks writes with `fcntl.flock` on the `.lock` file in
  `cert_dir` (not on Windows, not reliable on NFS).
- `StorageVault` with KV v2 uses check-and-set. KV v1 is not atomic.
- A custom storage is atomic only when it overrides `increase_counter`,
  `replace_last_keys` and `update_metadata`, see below.

`WrapJWK` keeps the loaded keys, create a new `WrapJWK` and `WrapJWT` for each
thread.

## Custom storage

A custom storage, for example a database, must be a subclass of
[`AbstractKeyStorage`](../joserfc_wrapper/AbstractKeyStorage.py)
and implement:

- `get_last_kid()` - the last Key ID
- `load_keys(kid="")` - returns `(kid, {"data": keys})`, the last keys for
  an empty `kid`
- `save_keys(kid, keys)` - saves the keys and sets them as the last keys
- `_save_last_id(kid)` - sets the last Key ID

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

[< Previous: Getting started](./getting-started.md) |
[Contents](./index.md) |
[Next: Signature keys >](./keys.md)
