# Verifying services (JWKS)

How other services verify tokens without access to the private keys.

## What is JWKS

A JWKS (JSON Web Key Set, RFC 7517) is a public JSON document with the
**public** keys which verify the signatures of your tokens. It is usually
published at `https://<issuer>/.well-known/jwks.json`:

```json
{
  "keys": [
    {"kid": "8cb0...", "kty": "EC", "crv": "P-256", "x": "...", "y": "...",
     "use": "sig", "alg": "ES256"},
    {"kid": "2a34...", "kty": "EC", "crv": "P-256", "x": "...", "y": "...",
     "use": "sig", "alg": "ES256"}
  ]
}
```

A public key can only verify a signature, nobody can sign a token with it.
That is why the JWKS can be public. A token has the Key ID (`kid`) in its
header, the verifier finds the key with the same `kid` in the JWKS and
checks the signature. The JWKS contains also the retired keys, so tokens
signed before a key rotation stay valid until they expire.

## Why use it

Without JWKS every service which verifies tokens needs access to the storage
with the keys (Vault, Redis, files), and the storage contains also the
private keys. With JWKS:

- **One issuer, more services.** The service which creates tokens (e.g. the
  login) keeps the private keys. The services which only accept tokens (APIs,
  microservices) get only the public JWKS and no access to Vault. An attacker
  who breaks into such a service cannot create tokens.
- **Other technologies.** JWKS is a standard. API gateways (nginx, Kong,
  Traefik, Envoy), services in Go, Node.js or Java and your partners verify
  your tokens with any JWT library, they need only the URL of the JWKS.
- **Key rotation without coordination.** New keys are in the JWKS
  immediately after a rotation. The verifiers download the JWKS again when
  they see an unknown `kid`, nothing has to be sent or restarted.
- **Performance and availability.** The verifiers keep the JWKS in memory
  and do not read any storage for each request. An outage of Vault does not
  stop verifying tokens.

| | Storage access | JWKS |
| --- | --- | --- |
| Verifying a token | reads the storage (cached) | from memory |
| The verifier needs | access to the private keys | only the public JWKS |
| Verifying by other technologies | not possible | standard JWKS URL |
| A broken verifying service | can create tokens | cannot create tokens |

## Publish the JWKS

The service which creates the tokens publishes the JWKS, for example from
an endpoint of your application:

```python
from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/.well-known/jwks.json")
def jwks():
    # storage: the shared storage object of the application
    return jsonify(WrapJWK(storage).jwks())
```

The same with FastAPI:

```python
@app.get("/.well-known/jwks.json")
def jwks() -> dict:
    return WrapJWK(storage).jwks()
```

Or write it to a file served by a web server, for example from cron after
each rotation (the file is replaced atomically):

```bash
genjw jwks --output=/var/www/html/.well-known/jwks.json
```

- The JWKS contains all keys in the storage except the revoked keys: the
  last keys and the retired keys. `prune` deletes old keys, see
  [Delete old keys](./keys.md#delete-old-keys-prune).
- It never contains the private keys or the secret keys of JWE.
- `jwks()` needs a storage which can list keys, Vault needs the `list`
  capability, see [Vault policy](./storage.md#vault-policy).
- Publish it over HTTPS. Whoever can change the JWKS on the way can add own
  keys and create valid tokens.

## Verify with the JWKS

A service which only verifies tokens uses `StorageJWKS` instead of a storage
with the keys. `verify` works the same way:

```python
from joserfc_wrapper import StorageJWKS, WrapJWK, WrapJWT

# create it once and share it in the application
storage = StorageJWKS("https://auth.example.com/.well-known/jwks.json")

# once, shared by all threads
myjwt = WrapJWT(WrapJWK(storage), issuer="https://example.com", audience="api")

# for each request
verified = myjwt.verify(token)
```

- The source is a `https://` URL, or a file (a path or `file://`).
  `http://` is refused, `allow_http=True` allows it in a trusted network.
- `ttl` (default 300 seconds): the JWKS is downloaded again after it.
- `refresh_interval` (default 60 seconds): a token with an unknown `kid`
  (e.g. new keys after a rotation) downloads the JWKS again at once, at most
  once in this interval. Tokens with random `kid` values do not overload
  the source.
- `max_stale` (default 3600 seconds): when the source is not available, the
  last downloaded JWKS is used at most this long, then `verify` raises
  `KeysLoadError` (HTTP 500).
- `timeout` and `session`: timeout of the request and a `requests.Session`
  for proxies, own CA certificates or authentication.
- `StorageJWKS` can only verify tokens. `create`, key management,
  `revoke_token` and `WrapJWE.decrypt` (the JWKS has no secret keys) raise
  an error.

```python
import requests

session = requests.Session()
session.verify = "/etc/ssl/certs/internal-ca.pem"
storage = StorageJWKS(
    "https://auth.internal/.well-known/jwks.json",
    ttl=600,
    timeout=2,
    session=session,
)
```

## What to watch out for

- **Revoked tokens are not visible.** The revocation of single tokens
  (`revoke_token`, see [Revoke tokens](./verify.md#revoke-tokens)) needs the
  storage, the JWKS does not contain it. `WrapJWT(revocation=True)` with
  `StorageJWKS` raises `ConfigurationError`. Services which must reject
  revoked tokens need the storage.
- **A revoked key is rejected after the next download.** A revoked key
  disappears from the JWKS, the verifiers download it again after `ttl` at
  the latest, then `verify` raises `TokenKidUnknownError`. Use a shorter
  `ttl` for faster reaction.
- **Only ES256 keys of this library.** Keys of other types in the JWKS are
  ignored, JWKS of other issuers (OIDC providers) are not supported.

[< Previous: Verifying tokens](./verify.md) |
[Contents](./index.md) |
[Next: Encrypted data (JWE) >](./jwe.md)
