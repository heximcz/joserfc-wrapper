# Documentation for CLI

The library includes a key and token generator for creating new signature keys and tokens or verifying existing ones.

### Show help
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
export VAULT_TOKEN="<vault token>
```

The `--storage` switch does not need to be defined in this case since the default storage is `vault`.

Create first keys

```bash
genjw keys
# output
# New keys has been saved in 'vault' storage with KID: '5b0be60b1c91438...'.
```

Create JWT token

```bash
# Minimal
genjw token --iss="https//example.tld" --aud="auditor" --uid=123
# Full
genjw token --iss="https//example.tld" --aud="auditor" --uid=123 --exp='minutes=10' --custom="{var1:value1,var2:value2}"
# output
# eyJ0eXAiOiJKV1QiLCJhbGc...
```

Validate JWT token

```bash
genjw check --iss="https//example.tld" --aud="auditor" --token="eyJ0eXAiOiJKV1QiLCJhbGc..."
# output
# Token is valid.
```

Show headers and claims

```bash
genjw show --token="eyJ0eXAiOiJKV1QiLCJhbGc..."
genjw show --token="eyJ0eXAiOiJKV1QiLCJhbGc..." --headers=True
# output
# Header: {'typ': 'JWT', 'alg': 'ES256', 'kid': '8cb0...'}
# Claims: {'iss': 'https//example.tld', 'aud': 'auditor', 'uid': 123, 'iat': 170...}
```

## File storage

Configure environment

```bash
export CERT_DIR="/tmp"
```

Create first keys

```bash
genjw keys --storage=file
# New keys has been saved in 'vault' storage with KID: 'eyJ0eXAiOiJKV1QiLCJhbGc...'.
```

Create JWT token

```bash
# Minimal
genjw token --iss="https//example.tld" --aud="auditor" --uid=123 --storage=file
# Full
genjw token --iss="https//example.tld" --aud="auditor" --uid=123 --exp='minutes=10' --custom="{var1:value1,var2:value2}" --storage=file
# output
# eyJ0eXAiOiJKV1QiLCJhbGc...
```

Validate JWT token

```bash
genjw check --iss="https//example.tld" --aud="auditor" --token="eyJ0eXAiOiJKV1QiLCJhbGc..." --storage=file
# output
# Token is valid.
```

Show headers and claims

```bash
genjw show --token="eyJ0eXAiOiJKV1QiLCJhbGc..." --storage=file
genjw show --token="eyJ0eXAiOiJKV1QiLCJhbGc..." --headers=True --storage=file
# output
# Header: {'typ': 'JWT', 'alg': 'ES256', 'kid': '8cb0...'}
# Claims: {'iss': 'https//example.tld', 'aud': 'auditor', 'uid': 123, 'iat': 170...}
```

## Using payload switch

When generating the token, you can set the `--payload` switch to a value higher than zero. This will check how many times the signature key was used to sign the token. If the value limit is exceeded, a new signature key will be automatically generated to sign a new token. This feature enhances security by ensuring that if the given signature key is leaked or compromised, only a certain portion of the token will be affected.

```bash
genjw token --iss="https//example.tld" --aud="auditor" --uid=123 --payload=10
```

### Errors

Exceptions are listed in the following format: `exception name` : `error`. For instance:
```bash
Invalid: BadSignatureError : bad_signature:
# or
Invalid: InvalidClaimError : invalid_claim: Invalid claim: "iss"
```

[< back to index](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/index.md)

