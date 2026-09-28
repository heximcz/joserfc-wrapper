# Encrypted data (JWE)

Secret data inside tokens, encrypted by the secret key of the signature keys.

## Create token with encrypted data

```python
try:
    myjwe = WrapJWE(wrapjwk=myjwk)

    # encrypt secret data (str or bytes) by the last keys,
    # the Key ID is saved in the header of the encrypted data
    claims_with_sec = {
        "uid": 123,
        "sec": myjwe.encrypt(data="very secret text"),
        "sec_bytes": myjwe.encrypt(data=b"very secret bytes"),
    }

    token_with_sec = myjwt.create(claims=claims_with_sec)
except Exception as e:
    print(f"{type(e).__name__}: {e}")
```

## Decrypt secret data

```python
try:
    valid_token = myjwt.verify(token_with_sec)

    myjwe = WrapJWE(wrapjwk=myjwk)
    # the key is selected by kid in the header of the encrypted data,
    # data encrypted by versions older than 0.3.0 have no kid in the
    # header, they are decrypted by the last keys or by the kid parameter
    secret_data = myjwe.decrypt(valid_token.claims["sec"])
    secret_data_bytes = myjwe.decrypt(valid_token.claims["sec_bytes"])
    print(f"[sec]: {secret_data}")  # b'very secret text'
    print(f"[sec_bytes]: {secret_data_bytes}")  # b'very secret bytes'
except Exception as e:
    print(f"{type(e).__name__}: {e}")
```

[< Previous: Verifying tokens](./verify.md) |
[Contents](./index.md) |
[Next: Security notes for developers >](./security.md)
