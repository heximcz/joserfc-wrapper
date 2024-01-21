#!/usr/bin/env python3
import os
import sys
import fire
import datetime
from datetime import timezone
from joserfc_wrapper import StorageVault, StorageFile, WrapJWK, WrapJWT
from joserfc_wrapper.exceptions import CreateTokenException

class generate_jwt_tokens:
    """
    Generate JWT
    """

    def __init__(self, storage: str = "vault") -> None:
        self.storage = storage
        if storage == "vault":
            vars = ["VAULT_ADDR", "VAULT_TOKEN", "VAULT_MOUNT"]
            if not all(var in os.environ for var in vars):
                print(f"Missing var(s) in environment: {' or '.join(vars)}.")
                sys.exit(1)
            self.vault_addr = os.environ['VAULT_ADDR']
            self.vault_token = os.environ['VAULT_TOKEN']
            self.vault_mount = os.environ['VAULT_MOUNT']
        elif storage == "file":
            self.cert_dir = os.environ['CERT_DIR']
            if self.cert_dir is None:
                print("Missing var in environment: CERT_DIR")
                sys.exit(1)
        else:
            print("Allowed value is: --storage='vault' (default) or 'file'")
            sys.exit(1)

    def token(
        self,
        iss: str,
        aud: str,
        uid: int,
        exp: str = None,
        custom: dict = None,
        payload: int = 0,
    ) -> None:
        """
        Create new JWT token.

        Required arguments:
            --dir=<path>: str
            --iss=<issuer>: str
            --aud=<audince>: str
            --uid=<id>: int
        Optional arguments:
            --exp=<expire after>: str
            --custom=<custom data>: dict
            --payload=<signed key payload>
            examples:
                --exp="minutes=5" - valid units: "seconds=int" | "minutes=int" | "days=int" | "hours=int" | "weeks=int"
                --custom="{var1:value1,var2:value2,...}"
                --payload=5
        """
        if self.storage == "vault":
            wjwk = WrapJWK(StorageVault(self.vault_addr,self.vault_token,self.vault_mount))
        elif self.storage == "file":
            if not os.path.exists(self.cert_dir):
                return f"Error: directory {self.cert_dir} not exist."
            wjwk = WrapJWK(StorageFile(self.cert_dir))

        # basic claims
        claims = {
            "iss": iss,
            "aud": aud,
            "uid": uid,
        }

        # add expiration if possible
        if exp:
            # check format
            if not ("=" in exp):
                return f"Error: --exp={exp} bad format."
            parts = exp.split("=")
            valid_units = {"seconds", "minutes", "days", "hours", "weeks"}
            # check valid units
            if not parts[0] in valid_units:
                return f'Error: "{parts[0]}" in --exp is not in valid units: {valid_units}.'
            # check neno zero value
            if not int(parts[1]) > 0:
                return f"Error: --exp={exp} value must be greater zero."
            # Compute expiration and add to claims
            kwargs = {parts[0]: int(parts[1])}
            claims["exp"] = datetime.datetime.now(
                tz=timezone.utc
            ) + datetime.timedelta(**kwargs)

        # add custom to claims if exist and is dist
        if custom:
            if not isinstance(custom, dict):
                return f"Error: --custom must be a dict."
            for key, value in custom.items():
                if key not in claims:
                    claims[key] = value


#        print(claims)
        # ok do token
        try:
            wjwt = WrapJWT(wjwk)
            if payload:
                if not isinstance(payload, int):
                    return f"Error: --payload must be a int."
                if payload > 0:
#                    print(f"payload={payload}")
                    return wjwt.create(claims=claims, payload=payload)
            else:
                return wjwt.create(claims=claims)
        except CreateTokenException as e:
            return f"Error: {str(e)}"

        # # create token
        # try:
        #     create_token = CreateJwtToken(cert_dir=dir, payload=payload)
        #     if create_token.create():
        #         return f"Token: {create_token.get_token()}"
        # except CreateTokenException as e:
        #     return f"CreateTokenException: {e}"

    # def keys(self, dir: str) -> None:
    #     """
    #     Create new PEM KEYS and save it in DIR

    #     Required argument:
    #         --dir=<path>: str
    #     """
    #     if not os.path.exists(dir):
    #         return f"Error: Is there a {dir} directory?"

    #     # create keys
    #     es512 = Es512KeysManger()
    #     es512.generate_new_keys()
    #     if not es512.save_new_keys(cert_dir=dir):
    #         return f"Error: Keys not generated."

    #     k_priv = os.path.join(dir, f"{es512.get_root_filename()}.pem")
    #     k_pub = os.path.join(dir, f"{es512.get_root_filename()}-public.pem")

    #     return f"New keys has been saved in {k_pub} and {k_priv} files."

    # def check(self, token: str, dir: str, aud: str) -> None:
    #     """
    #     Check validity of a token

    #     Required arguments:
    #         --dir=<path>: str
    #         --aud=<audience>: str
    #         --token=<jwt token>: str
    #     """
    #     if not os.path.exists(dir):
    #         return f"Error: Is there a {dir} directory?"

    #     try:
    #         jwt_token = VerifyJwtToken()
    #         if jwt_token.validate(token=token, audience=aud, cert_dir=dir):
    #             return f"Token is valid.\n{jwt_token}"
    #     except InvalidTokenException as e:
    #         return f"InvalidTokenException: {e}"


def run():
    fire.Fire(generate_jwt_tokens)


if __name__ == "__main__":
    run()
