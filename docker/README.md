# Development environment

This directory is for development and testing of `joserfc-wrapper` only.
It is not part of the published package and must not be used in production.

## Services

- `dev` - Python 3.10 (the oldest supported version) with the project and dev
  dependencies installed by Poetry, the source code is mounted to `/app`.
- `vault` - HashiCorp Vault in dev mode (in-memory storage, root token
  `dev-root`), available on `127.0.0.1:8200`.
- `vault-init` - creates the KV mounts `jwt` (KV v2) and `jwt-v1` (KV v1).
- `redis` - Redis 6.2 (the oldest supported version) without persistence,
  available on `127.0.0.1:6379`.
- `redis-c1`, `redis-c2`, `redis-c3` and `redis-cluster-init` - Redis
  Cluster (Redis 7.4, 3 masters) for the tests of `StorageRedis` with
  `redis.RedisCluster`.

The `dev` container has `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_MOUNT`,
`VAULT_MOUNT_V1`, `CERT_DIR`, `REDIS_URL` and `REDIS_CLUSTER_URL` set, so
`genjw` and the Vault and Redis tests work without any configuration.

## Usage

Run from the project root, see `Makefile`:

```bash
make build        # build the image
make up           # start in foreground
make up-daemon    # start in background
make down         # stop and remove containers
make test         # run all tests including Vault and Redis
make test t=tests/test_jwt.py args="-k decode"
```

Another Python version can be used by
`PYTHON_VERSION=3.13 make build`, another Redis version by
`REDIS_VERSION=8 make up`.
