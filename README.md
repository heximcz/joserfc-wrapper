### The `joserfc-wrapper` library simplifies the use of JWT and automates the management of signature keys.

#### Install
`pip install joserfc-wrapper`

#### Reason

The main purpose of this wrapper is to simplify the management of signature keys for generating JWT tokens using the [joserfc]((https://github.com/authlib/joserfc)) library and adhering to RFC standards. It offers two options for managing signature keys: securely storing generated keys in [HashiCorp Vault](https://github.com/hvac/hvac) (default) or storing them on the filesystem (optional).  Additionally, it facilitates the use of JWT tokens in projects.

#### Need a custom solution for storing keys? We've got you covered.

If necessary, a custom object can be created to manage signing keys, including storing them in a database. However, this custom class must be a subclass of the parent [AbstractKeyStorage](https://github.com/heximcz/joserfc-wrapper/blob/main/joserfc_wrapper/AbstractKeyStorage.py) abstract class to implement the necessary methods.

#### Configuration

```python
# file storage
storage = StorageFile(
    cert_dir="/tmp"
)

# HashiCorp Vault storage
storage = StorageVault(
    url="<vault url>,
    token="<token>",
    mount="<secure mount>"
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

#### Create new signature keys
```python
from hvac.exceptions import InvalidPath

from joserfc_wrapper.exceptions import ObjectTypeError
from joserfc_wrapper import WrapJWK, StorageVault, StorageFile


""" With file storage """
file = StorageFile(cert_dir="/tmp")
myjwk = WrapJWK(storage=file)

""" With Vault storage """
vault = StorageVault(
    url="<vault url>,
    token="<token>",
    mount="<secure mount>"
    )
myjwk = WrapJWK(storage=vault)

# generate a new keys
myjwk.generate_keys()
# save new keys to a storage
myjwk.save_keys()
```

#### Examples

```python
""" Required claims """
claims = {
    "iss": "https://example.com",
    "aud": "auditor",
    "uid": 123,
}

try:
    """ Create token """
    myjwt = WrapJWT(wrapjwk=myjwk)
    # only the last generated key is always used to create a new token
    token = myjwt.create(claims=claims)
    print(f"Token: {token[:20]}...,  Length: {len(token)}bytes")

    """ Create token with encrypted data """
    myjwe = WrapJWE(wrapjwk=myjwk)
    secret_data = "very secret text"
    secret_data_bytes = b"very secrets bytes"
    claims["sec"] = myjwe.encrypt(data=secret_data)
    claims["sec_bytes"] = myjwe.encrypt(data=secret_data_bytes)
    print(f'[sec]: {claims["sec"]}')
    token_with_sec = myjwt.create(claims=claims)
    print(f"Token: {token_with_sec[:20]}..., Length: {len(token_with_sec)}bytes")

    """ Validate token """
    try:
        myjwt = WrapJWT(wrapjwk=myjwk)
        # return extracted token object Token
        valid_token = myjwt.decode(token=token)
        print(valid_token.header)
        print(valid_token.claims)
    except BadSignatureError as e:
        print(f"{e}")

    # check if claims in token are valid
    invalid_claims = {
        "aud": "any",
        "iss": "any"
    }

    try:
        myjwt.validate(token=valid_token, claims=invalid_claims)
    except InvalidClaimError as e:
        # invalid_claim: Invalid claim: "iss"
        print(e)

    """ Validate invalid token (signature key not exist) """
    try:
        token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjM5MTkxZDUyM2Q4MTQ3NTZiYTgxMWNmZWFjODY0YjNjIn0.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXVkIjoiYXVkaXRvciIsInVpZCI6MTIzLCJpYXQiOjE3MDUyNzc3OTR9.r7uflHLnSIMxhma0eU_A7hRupL3ZDUjXGgSMprOmWdDzMh1TRDFxW8CPzOhnVDZLfPeyjjt4KYn6jPT2W2E9jg"
        myjwt = WrapJWT(wrapjwk=myjwk)
        # here is raise InvalidPath because kid not in a storage
        valid_token = myjwt.decode(token=token)
    except InvalidPath as e:
        print(f"{e}")

    """ Validate fake token """
    try:
        token = "faketoken"
        myjwt = WrapJWT(wrapjwk=myjwk)
        # here is raise InvalidPath because kid not in a storage
        valid_token = myjwt.decode(token=token)
    except ValueError as e:
        print(f"{e}")

    """ Validate token and decrypt secret data """
    myjwt = WrapJWT(wrapjwk=myjwk)
    myjwe = WrapJWE(wrapjwk=myjwk)
    valid_token = myjwt.decode(token=token_with_sec)
    # decrypt return b'' in all situations
    secret_data = myjwe.decrypt(valid_token.claims["sec"], myjwt.get_kid())
    secret_data_bytes = myjwe.decrypt(valid_token.claims["sec_bytes"], myjwt.get_kid())
    print(f"[sec]: {secret_data}")
    print(f"[sec_bytes]: {secret_data_bytes}")

except InvalidPath as e:
    # create JWK first
    print(f"Invalid path because key not exist in the storage.")
    print(f"{e}")
```

#### A bit of magic
By default, it is possible to sign an unlimited number of tokens with a single key. However, this approach may not always be appropriate. Instead, a more efficient solution can be implemented by setting the payload as the maximum number of tokens that can be signed with the same key, thus saving storage space. It is important to keep in mind that the keys are stored, so a suitable compromise must be found when setting the payload to avoid storage overflow.

```python
""" payload """
token = myjwt.create(claims=claims, payload=10)
print(f"Token: {token[:30]}...,  Length: {len(token)}bytes")
```

#### Exceptions
For debugging is there are a few exceptions which can be found here:
- [`joserfc exceptions`](https://github.com/authlib/joserfc/blob/main/src/joserfc/errors.py)
- [`hvac exceptions`](https://hvac.readthedocs.io/en/stable/source/hvac_exceptions.html)
- [`build-in ecxceptions`](https://github.com/heximcz/joserfc-wrapper/blob/main/joserfc_wrapper/exceptions.py)


#### Contributions to the development of this library are welcome, ideally in the form of a pull request.
