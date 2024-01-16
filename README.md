# In progress!


#### Configuration
```bash
# Configure environment. For example in .venv/bin/activate:

# env for HashiCorp Vault storage
export VAULT_URL="http://localhost:8200"
export VAULT_TOKEN="<token>"
export VAULT_MOUNT="<secret mount>"

# env for file storage
export CERT_DIR="/tmp"
```

#### Create new signature keys
```python
from hvac.exceptions import InvalidPath

from joserfc_wrapper.exceptions import ObjectTypeError
from joserfc_wrapper import WrapJWK, StorageVault, StorageFile

"""
The default repository for signature keys is HashiCorp Vault, but there
is also the option to store keys in standard disk files. If neither
option is suitable, it is possible to write your own object for
manipulating signature keys (e.g., for storing them in a database).
However, this custom class must be a descendant of the abstract class
AbstractKeyStorage to implement the required methods.
"""

# select one buit-in storage handler

# default os.environ["CERT_DIR"]
#
# file_storage = StorageFile(
#     cert_dir="/tmp"
# )

# default:
# url: str = os.environ["VAULT_URL"],
# token: str = os.environ["VAULT_TOKEN"],
# mount: str = os.environ["VAULT_MOUNT"]
#
# vault_storage = StorageVault(
#     url="any uri",
#     token="any token",
#     mount="any vault mount",
# )

try:
    """ File storage """

    file_storage = StorageFile()
    myjwk = WrapJWK(storage=file_storage)
 
    # generate a new keys
    myjwk.generate_keys()
 
    # save new keys to a storage
    myjwk.save_keys()
    print(f"Key ID (kid): {myjwk.get_kid()}")
 
    # test load generated keys - TODO: is need load in public?
    myjwk.load_keys()
    print(f"Key ID (kid): {myjwk.get_kid()}")

    """ Vault storage """

    myjwk = WrapJWK()
 
    # generate a new keys
    myjwk.generate_keys()
 
    # save new keys to a storage
    myjwk.save_keys()
    print(f"Key ID (kid): {myjwk.get_kid()}")
 
    # test load generated keys - TODO: is need load in public?
    myjwk.load_keys()
    print(f"Key ID (kid): {myjwk.get_kid()}")

except ObjectTypeError as e:
    print(f"{e}")
```

#### JWT - Examples with Vault storage

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
    """ Create basic token """

    myjwk = WrapJWK()
    # load last key
    myjwk.load_keys()
    # JWT vith last key
    myjwt = WrapJWT(myjwk)
    # only the last generated key is always used to create a new token
    token = myjwt.create(claims=claims)
    print(f"Token: {token[:20]}...,  Length: {len(token)}bytes")

    """ Create token with encrypted data """

    myjwe = WrapJWE(myjwk)
    secret_data = "very secret text"
    claims["sec"] = myjwe.encrypt(data=secret_data)
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
        # if keys are not for this token: BadSignatureError: bad_signature:
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

    # check if claims in token is valid
    valid_claims = {
        "iss": "https://example.com",
        "aud": "auditor",
    }
    try:
        myjwt.validate(token=valid_token, valid_claims=valid_claims)
    except InvalidClaimError as e:
        # no error here
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

    """ Validate token and decrypt secret data in ["sec"] """

    myjwt = WrapJWT()
    myjwe = WrapJWE(myjwk)
    valid_token = myjwt.decode(token=token_with_sec)
    secret_data = myjwe.decrypt(valid_token.claims["sec"], myjwt.get_kid())
    print(f"My very secret data: {secret_data}")

except InvalidPath as e:
    # create JWK first
    print(f"Invalid path, probably key not exist in a storage.")
    print(f"{e}")

```