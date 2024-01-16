### `joserfc-wrapper` is a library for easy use of JWT and automatic management of signature keys.


#### Reason

This wrapper's main purpose is to simplify the management of signature keys
for generating JWT tokens and to use RFC for creating keys and tokens using
the [joserfc](https://github.com/authlib/joserfc) library. For managing signature keys, it implements two options.
The default option is to securely store generated keys in [HashiCorp Vault](https://github.com/hvac/hvac).
An optional feature is then the storage of generated keys on the filesystem.
Last but not least, it is the simple use of JWT tokens in our projects.


#### Custom key storage solution? Of course.
The default repository for signature keys is HashiCorp Vault, but there
is also the option to store keys in files. If neither option is
suitable, it is possible to write your own object for manipulating
signature keys (e.g., for storing them in a database).
However, this custom class must be a subclass of the parent abstract class
[AbstractKeyStorage](https://github.com/heximcz/joserfc-wrapper/blob/main/joserfc_wrapper/AbstractKeyStorage.py) to implement the required methods.

#### Storage configuration
```bash
# Configure environment. For example in .venv/bin/activate:

# env for HashiCorp Vault storage kv/v1
export VAULT_URL="http://localhost:8200"
export VAULT_TOKEN="<token>"
export VAULT_MOUNT="<secret mount>"

# env for file storage
export CERT_DIR="/tmp"
```
configuration can also be done in a script

```python
# file storage
storage = StorageFile(
    cert_dir="/tmp"
)

# HashiCorp Vault storage
storage = StorageVault(
    url="any uri",
    token="any token",
    mount="any vault mount",
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
file = StorageFile()
myjwk = WrapJWK(storage=file)

""" With Vault storage """
myjwk = WrapJWK()

# generate a new keys
myjwk.generate_keys()
# save new keys to a storage
myjwk.save_keys()
```

#### Examples with Vault storage

```python
from hvac.exceptions import InvalidPath
from joserfc.errors import InvalidClaimError, BadSignatureError

from joserfc_wrapper import WrapJWT, WrapJWE, WrapJWK

"""
Default storage is Vault
"""

""" Required claims """
claims = {
    "iss": "https://example.com",
    "aud": "auditor",
    "uid": 123,
}

try:
    """ Create token """

    myjwt = WrapJWT()
    # only the last generated key is always used to create a new token
    token = myjwt.create(claims=claims)
    print(f"Token: {token[:20]}...,  Length: {len(token)}bytes")


    """ Create token with encrypted data """

    myjwe = WrapJWE()
    secret_data = "very secret text"
    secret_data_bytes = b"very secrets bytes"
    claims["sec"] = myjwe.encrypt(data=secret_data)
    claims["sec_bytes"] = myjwe.encrypt(data=secret_data_bytes)
    print(f'[sec]: {claims["sec"]}')
    token_with_sec = myjwt.create(claims=claims)
    print(f"Token: {token_with_sec[:20]}..., Length: {len(token_with_sec)}bytes")


    """ Validate token """

    try:
        myjwt = WrapJWT()
        # return extracted token object Token
        valid_token = myjwt.decode(token=token)
        print(valid_token.header)
        print(valid_token.claims)
    except BadSignatureError as e:
        print(f"{e}")

    # check if claims in token is valid
    invalid_claims = {
        "aud": "any",
        "iss": "any"
    }

    try:
        myjwt.validate(token=valid_token, valid_claims=invalid_claims)
    except InvalidClaimError as e:
        # invalid_claim: Invalid claim: "iss"
        print(e)

    """ Validate invalid token (signature key not exist) """

    try:
        token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjM5MTkxZDUyM2Q4MTQ3NTZiYTgxMWNmZWFjODY0YjNjIn0.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXVkIjoiYXVkaXRvciIsInVpZCI6MTIzLCJpYXQiOjE3MDUyNzc3OTR9.r7uflHLnSIMxhma0eU_A7hRupL3ZDUjXGgSMprOmWdDzMh1TRDFxW8CPzOhnVDZLfPeyjjt4KYn6jPT2W2E9jg"
        myjwt = WrapJWT()
        # here is raise InvalidPath because kid not in a storage
        valid_token = myjwt.decode(token=token)
    except InvalidPath as e:
        print(f"{e}")


    """ Validate fake token """

    try:
        token = "faketoken"
        myjwt = WrapJWT()
        # here is raise InvalidPath because kid not in a storage
        valid_token = myjwt.decode(token=token)
    except ValueError as e:
        print(f"{e}")


    """ Validate token and decrypt secret data """

    myjwt = WrapJWT()
    myjwe = WrapJWE()
    valid_token = myjwt.decode(token=token_with_sec)
    # decrypt return b'' in all situations
    secret_data = myjwe.decrypt(valid_token.claims["sec"], myjwt.get_kid())
    secret_data_bytes = myjwe.decrypt(valid_token.claims["sec_bytes"], myjwt.get_kid())
    print(f"[sec]: {secret_data}")
    print(f"[sec_bytes]: {secret_data_bytes}")

    print(f"Done")

except InvalidPath as e:
    # create JWK first
    print(f"Invalid path because key not exist in the storage.")
    print(f"{e}")
```

#### In case you are using a different storage than the default vault storage:

```python
try:
    """ Create token """

    file = StorageFile()
    jwk_file = WrapJWK(storage=file)
    myjwt = WrapJWT(jwk_file)
    # only the last generated key is always used to create a new token
    token = myjwt.create(claims=claims)
    print(f"Token: {token[:20]}...,  Length: {len(token)}bytes")


    """ Create token with encrypted data """

    myjwe = WrapJWE(jwk_file)
    secret_data = "very secret text"
    secret_data_bytes = b"very secrets bytes"
    claims["sec"] = myjwe.encrypt(data=secret_data)
    claims["sec_bytes"] = myjwe.encrypt(data=secret_data_bytes)
    print(f'[sec]: {claims["sec"]}')
    token_with_sec = myjwt.create(claims=claims)
    print(f"Token: {token_with_sec[:20]}..., Length: {len(token_with_sec)}bytes")


    """ Validate token """

    try:
        myjwt = WrapJWT(jwk_file)
        # return extracted token object Token
        valid_token = myjwt.decode(token=token)
        print(valid_token.header)
        print(valid_token.claims)
    except BadSignatureError as e:
        print(f"{e}")

    # check if claims in token is valid
    invalid_claims = {
        "aud": "any",
        "iss": "any"
    }

    try:
        myjwt.validate(token=valid_token, valid_claims=invalid_claims)
    except InvalidClaimError as e:
        # invalid_claim: Invalid claim: "iss"
        print(e)


    """ Validate invalid token (signature key not exist) """

    try:
        token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjM5MTkxZDUyM2Q4MTQ3NTZiYTgxMWNmZWFjODY0YjNjIn0.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXVkIjoiYXVkaXRvciIsInVpZCI6MTIzLCJpYXQiOjE3MDUyNzc3OTR9.r7uflHLnSIMxhma0eU_A7hRupL3ZDUjXGgSMprOmWdDzMh1TRDFxW8CPzOhnVDZLfPeyjjt4KYn6jPT2W2E9jg"
        myjwt = WrapJWT(jwk_file)
        # here is raise InvalidPath because kid not in a storage
        valid_token = myjwt.decode(token=token)
    except FileNotFoundError as e:
        print(f"{e}")


    """ Validate fake token """

    try:
        token = "faketoken"
        myjwt = WrapJWT(jwk_file)
        # here is raise InvalidPath because kid not in a storage
        valid_token = myjwt.decode(token=token)
    except ValueError as e:
        print(f"{e}")


    """ Validate token and decrypt secret data """

    myjwt = WrapJWT(jwk_file)
    myjwe = WrapJWE(jwk_file)
    valid_token = myjwt.decode(token=token_with_sec)
    # decrypt return b'' in all situations
    secret_data = myjwe.decrypt(valid_token.claims["sec"], myjwt.get_kid())
    secret_data_bytes = myjwe.decrypt(valid_token.claims["sec_bytes"], myjwt.get_kid())
    print(f"[sec]: {secret_data}")
    print(f"[sec_bytes]: {secret_data_bytes}")

except FileNotFoundError as e:
    # create JWK first
    print(f"Key not exist in the storage.")
    print(f"{e}")
```

#### Exceptions
For debuging is there are a few exceptions which can be found here:
- [`joserfc exceptions`](https://github.com/authlib/joserfc/blob/main/src/joserfc/errors.py)
- [`hvac exceptions`](https://hvac.readthedocs.io/en/stable/source/hvac_exceptions.html)
- [`build-in ecxceptions`](https://github.com/heximcz/joserfc-wrapper/blob/main/joserfc_wrapper/exceptions.py)


#### Anyone who wants to contribute to the development of this library is welcome. Ideally in the form of PR.
