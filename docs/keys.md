# Signature keys

## Create new signature keys

At least one key must exist in the storage before the first token is
created. The new keys become the last keys, which sign new tokens.

```python
myjwk = WrapJWK(storage=storage)

# generate new keys (EC P-256 for signing, oct 128 bits for JWE)
myjwk.generate_keys()
# save new keys to the storage
myjwk.save_keys()
```

## Key rotation

By default (`payload=0`) the keys are never rotated automatically and a single
key signs an unlimited number of tokens. The `payload` parameter sets the
maximum number of tokens signed by a key. When the key reaches it, new keys
are generated and saved as the last keys. If a key is leaked or compromised,
only a limited number of tokens is affected.

```python
token = myjwt.create(claims={"uid": 123}, payload=10)
```

The old keys stay in the storage, so older tokens and encrypted data can be
still verified and decrypted. The keys are never deleted, so each rotation
adds new keys to the storage. Choose the payload with this in mind.

The counter of signed tokens is saved for every token, also with the default
`payload=0`. After increasing the payload, the keys are rotated by the real
number of tokens signed by the key.

Keys can be rotated manually by `generate_keys` and `save_keys`.

[< Previous: Storages](./storage.md) |
[Contents](./index.md) |
[Next: Tokens >](./tokens.md)
