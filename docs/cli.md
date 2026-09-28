# CLI

The library includes the `genjw` command for creating new signature keys and
tokens or verifying existing ones.

## Show help

```bash
genjw --help
genjw keys --help [--storage=file]
genjw token --help [--storage=file]
genjw check --help [--storage=file]
genjw show --help [--storage=file]
```

## Vault storage

Configure environment

```bash
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_MOUNT="<mount>"
export VAULT_TOKEN="<vault token>"
# optional, version of the KV secrets engine: 2 (default) or 1
export VAULT_KV_VERSION=2
```

KV v2 is safe for concurrent processes (check-and-set). Use
`VAULT_KV_VERSION=1` for keys saved by versions older than 0.3.0 in a KV v1
mount.

The `--storage` switch does not need to be defined in this case since the
default storage is `vault`.

Create first keys

```bash
genjw keys
# output
# New keys has been saved in 'vault' storage with KID: '5b0be60b1c91438...'.
```

Create JWT token

```bash
# Minimal (--exp is required)
genjw token --iss="https://example.tld" --aud="auditor" --uid=123 \
    --exp="hours=1"
# Full
genjw token --iss="https://example.tld" --aud="auditor" --uid=123 \
    --exp="minutes=10" --custom="{var1:value1,var2:value2}" --payload=10
# output
# eyJ0eXAiOiJKV1QiLCJhbGc...
```

Validate JWT token

```bash
genjw check --iss="https://example.tld" --aud="auditor" \
    --token="eyJ0eXAiOiJKV1QiLCJhbGc..."
# output
# Token is valid.
```

Show header and claims

```bash
genjw show --token="eyJ0eXAiOiJKV1QiLCJhbGc..."
genjw show --token="eyJ0eXAiOiJKV1QiLCJhbGc..." --header=True
# output
# Header: {'typ': 'JWT', 'alg': 'ES256', 'kid': '8cb0...'}
# Claims: {'iss': 'https://example.tld', 'aud': 'auditor', 'uid': 123, ...}
```

## File storage

Configure environment, the directory must exist

```bash
export CERT_DIR="/etc/myapp/keys"
```

Use the `--storage=file` switch with all commands.

Create first keys

```bash
genjw keys --storage=file
# output
# New keys has been saved in 'file' storage with KID: '541b3bdf155e4fd...'.
```

Create JWT token

```bash
genjw token --iss="https://example.tld" --aud="auditor" --uid=123 \
    --exp="hours=1" --storage=file
```

Validate JWT token

```bash
genjw check --iss="https://example.tld" --aud="auditor" \
    --token="eyJ0eXAiOiJKV1QiLCJhbGc..." --storage=file
```

Show header and claims

```bash
genjw show --token="eyJ0eXAiOiJKV1QiLCJhbGc..." --header=True --storage=file
```

## Token options

- `--exp` (required) - the token expires after the given time, units:
  `seconds`, `minutes`, `hours`, `days`, `weeks`, for example
  `--exp="hours=2"`. A token without expiration is invalid.
- `--custom` - other claims, they do not override the required claims.
- `--payload` - the maximum number of tokens signed by a key, 0 (default) =
  unlimited. When the key reaches it, a new signature key is generated
  automatically. If a signature key is leaked or compromised, only a limited
  number of tokens is affected. The old keys stay in the storage for
  verifying older tokens.

## Errors

Errors are printed to stderr and the command exits with code 1. Exceptions
are printed in the format `exception name: error`. For instance:

```bash
Error: --exp is required, e.g. --exp="hours=1". A token without expiration is invalid.
# genjw check prints the reason of an invalid token
Token is invalid. TokenExpiredError: Token has expired.
Token is invalid. TokenClaimError: Invalid claim in token.: Invalid claim: 'aud'
Token is invalid. TokenSignatureError: Invalid token signature.
```

`genjw check` verifies the signature, `exp` (required), `nbf`, `iss` and
`aud` (`--iss`, `--aud`).

[< Previous: Security notes for developers](./security.md) |
[Contents](./index.md) |
[Next: Upgrading >](./upgrading.md)
