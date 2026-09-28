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
# not safe for concurrent processes
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

## Concurrent processes

More processes can sign tokens with the same storage. The counter is
increased atomically and the keys are rotated only once, so a key never signs
more than `payload` tokens:

- `StorageFile` locks writes with `fcntl.flock` on the `.lock` file in
  `cert_dir` (not on Windows, not reliable on NFS).
- `StorageVault` with KV v2 uses check-and-set. KV v1 is not atomic.
- A custom storage is atomic only when it overrides `increase_counter` and
  `replace_last_keys`, see below.

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
}
```

For concurrent processes override also `increase_counter(kid, limit)` and
`replace_last_keys(last_kid, kid, keys)` with atomic implementations. The
default implementations use the methods above and are not atomic.

[< Previous: Getting started](./getting-started.md) |
[Contents](./index.md) |
[Next: Signature keys >](./keys.md)
