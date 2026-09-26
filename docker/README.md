# Development environment

This directory is for development and testing of `joserfc-wrapper` only.
It is not part of the published package and must not be used in production.

## Services

- `dev` - Python 3.10 (the oldest supported version) with the project and dev
  dependencies installed by Poetry, the source code is mounted to `/app`.
- `vault` - HashiCorp Vault in dev mode (in-memory storage, root token
  `dev-root`), available on `127.0.0.1:8200`.
- `vault-init` - creates the KV mounts `jwt` (KV v2) and `jwt-v1` (KV v1).

The `dev` container has `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_MOUNT`,
`VAULT_MOUNT_V1` and `CERT_DIR` set, so `genjw` and the Vault tests work
without any configuration.

## Usage

Run from the project root, see `Makefile`:

```bash
make build        # build the image
make up           # start in foreground
make up-daemon    # start in background
make down         # stop and remove containers
make test         # run all tests including Vault
make test t=tests/test_jwt.py args="-k decode"
```

Another Python version can be used by
`PYTHON_VERSION=3.13 make build`.
