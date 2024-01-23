# Documentation 

#### Storage configuration

```python
# file storage
storage = StorageFile(
    cert_dir="/tmp",
)

# HashiCorp Vault storage
storage = StorageVault(
    url="<vault url>",
    token="<token>",
    mount="<secure mount>",
)
```

#### Header and claims in this wrapper
```bash
# decoded header (all created automatically)
{
    'typ': 'JWT',    # created automatically
    'alg': 'ES256',  # created automatically
    'kid': 'cdfef1a0e8414b25a593e50c47e59dcb' # Key ID - created automatically
}
# decoded claims
{
    'iss': 'https://example.com', # required
    'aud': 'auditor',             # required
    'uid': 123,                   # required
    'iat': 1705418960             # created automatically
}
```
#### Import
```python
from joserfc_wrapper import (
    WrapJWK,
    WrapJWT,
    WrapJWE,
    StorageVault,
    StorageFile,
)
```

#### Create new signature keys
```python
myjwk = WrapJWK(storage=vault)

# generate a new keys
myjwk.generate_keys()
# save new keys to a storage
myjwk.save_keys()
```

#### Define required claims

```python
claims = {
    "iss": "https://example.com",
    "aud": "auditor",
    "uid": 123,
}
```

#### Create token
```python
try:
    myjwt = WrapJWT(wrapjwk=myjwk)
    # a new token is always created
    # using the most recent key generated.
    token = myjwt.create(claims=claims)
    print(
        f"Token: {token_with_sec[:20]}..., "
        f"Length: {len(token_with_sec)}bytes"
    )
except Exception as e:
    print(f"{type(e).__name__} : {str(e)}")
```

#### Create token with encrypted data
```python
try:
    myjwe = WrapJWE(wrapjwk=myjwk)
    
    # my very secret data
    secret_data = "very secret text"
    secret_data_bytes = b"very secrets bytes"
    
    # encrypt secure data
    claims["sec"] = myjwe.encrypt(
        data=secret_data
    )
    claims["sec_bytes"] = myjwe.encrypt(
        data=secret_data_bytes
    )

    myjwt = WrapJWT(wrapjwk=myjwk)
    token_with_sec = myjwt.create(claims=claims)

    print(
        f"Token: {token_with_sec[:20]}..., "
        f"Length: {len(token_with_sec)}bytes"
    )
except Exception as e:
    print(f"{type(e).__name__} : {str(e)}")
```

#### Token validation
```python
try:
    myjwt = WrapJWT(wrapjwk=myjwk)
    # return object Token
    valid_token = myjwt.decode(token=token)
    print(valid_token.header)
    print(valid_token.claims)
except Exception as e:
    print(f"{type(e).__name__} : {str(e)}")
```

#### Token validation - invalid claims
```python
invalid_claims = {
    "aud": "any",
    "iss": "any"
}

try:
    myjwt.validate(token=valid_token, claims=invalid_claims)
except Exception as e:
    print(f"{type(e).__name__} : {str(e)}")
```

#### Validate invalid token (signature key not exist)
```python
try:
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjM5MTkxZDUyM2Q4MTQ3NTZiYTgxMWNmZWFjODY0YjNjIn0.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXVkIjoiYXVkaXRvciIsInVpZCI6MTIzLCJpYXQiOjE3MDUyNzc3OTR9.r7uflHLnSIMxhma0eU_A7hRupL3ZDUjXGgSMprOmWdDzMh1TRDFxW8CPzOhnVDZLfPeyjjt4KYn6jPT2W2E9jg"
    myjwt = WrapJWT(wrapjwk=myjwk)
    # here is raise InvalidPath because kid not in a storage
    valid_token = myjwt.decode(token=token)
except Exception as e:
    print(f"{type(e).__name__} : {str(e)}")
```

#### Validate fake token
```python
try:
    token = "faketoken"
    myjwt = WrapJWT(wrapjwk=myjwk)
    # here is raise InvalidPath because kid not in a storage
    valid_token = myjwt.decode(token=token)
except Exception as e:
    print(f"{type(e).__name__} : {str(e)}")
```

#### Validate token and decrypt secret data
```python
try:
    myjwt = WrapJWT(wrapjwk=myjwk)
    valid_token = myjwt.decode(token=token_with_sec)

    myjwe = WrapJWE(wrapjwk=myjwk)
    secret_data = myjwe.decrypt(
        valid_token.claims["sec"],
        myjwt.get_kid(),
    )
    secret_data_bytes = myjwe.decrypt(
        valid_token.claims["sec_bytes"],
        myjwt.get_kid(),
    )
    print(f"[sec]: {secret_data}")
    print(f"[sec_bytes]: {secret_data_bytes}")

except Exception as e:
    print(f"{type(e).__name__} : {str(e)}")
```

## A bit of magic
By default, it is possible to sign an unlimited number of tokens with a single key. However, this approach may not always be appropriate. Instead, a more efficient solution can be implemented by setting the payload as the maximum number of tokens that can be signed with the same key, thus saving storage space. It is important to keep in mind that the keys are stored, so a suitable compromise must be found when setting the payload to avoid storage overflow.

```python
""" payload """
token = myjwt.create(claims=claims, payload=10)
print(f"Token: {token[:30]}...,  Length: {len(token)}bytes")
```

## Exceptions
For debugging is there are a few exceptions which can be found here:
- [`joserfc exceptions`](https://github.com/authlib/joserfc/blob/main/src/joserfc/errors.py)
- [`hvac exceptions`](https://hvac.readthedocs.io/en/stable/source/hvac_exceptions.html)
- [`build-in ecxceptions`](https://github.com/heximcz/joserfc-wrapper/blob/main/joserfc_wrapper/exceptions.py)


## CLI
[CLI documentation.](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/cli.md)


#### Contributions to the development of this library are welcome, ideally in the form of a pull request.
