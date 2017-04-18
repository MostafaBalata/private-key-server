REQUIRED_ENV_CONFIG_FIELDS = ["MASTER_ENTROPY"]
AUDIENCE = "Salesforce"
LOGIN_ALGORITHM = "ES512"
PUB_KEY_PATH = "ec512.pub.pem"
ISSUER = "Neufund"

PUBLIC_ECDSA_KEY = None


def read_keys():
    global PUBLIC_ECDSA_KEY
    with open(PUB_KEY_PATH, "r") as publicKey:
        PUBLIC_ECDSA_KEY = publicKey.read()


read_keys()
