import os

from bip32utils import BIP32Key
from ecdsa import BadSignatureError
from ethereum.utils import sha3
from flask import Flask, jsonify, request

import auth

app = Flask(__name__)
app.config.from_pyfile('config.py')

app.config.from_mapping(os.environ)

for key in app.config["REQUIRED_ENV_CONFIG_FIELDS"]:
    if key not in os.environ:
        raise EnvironmentError("Required env variable {} missing".format(key))

master_entropy = bytes.fromhex(app.config["MASTER_ENTROPY"])


def pub_to_addr(pub):
    assert (len(pub) == 64)
    return sha3(pub)[12:]


@app.route('/api/<int:uid>/sign', methods=['POST'])
@auth.verify_jwt(check=auth.verify_logged_in)
def sign_message_by_user(uid):
    user_entropy = sha3(b'%d%b' % (uid, master_entropy))
    user_private_key = BIP32Key.fromEntropy(user_entropy)
    message = request.get_json()["message"]
    binary_message = message.encode('utf-8')
    signature = user_private_key.k.sign(binary_message).hex()
    return jsonify({
        "signature": signature,
        "message": message
    })


@app.route('/api/<int:uid>/verify', methods=['POST'])
def verify_signed_message(uid):
    user_entropy = sha3(b'%d%b' % (uid, master_entropy))
    user_private_key = BIP32Key.fromEntropy(user_entropy)
    data = request.get_json()
    verifying_key = user_private_key.K
    signature = bytes.fromhex(data["signature"])
    message = data["message"].encode('utf-8')
    try:
        verifying_key.verify(signature, message)
        return jsonify({"ok": True})
    except BadSignatureError:
        return jsonify({"ok": False})


@app.errorhandler(403)
def forbidden(ex):
    return jsonify({"code": 403, "message": ex.description}), 403


@app.errorhandler(404)
def not_found(ex):
    return jsonify({"code": 404, "message": ex.description}), 404


if __name__ == '__main__':
    app.run()
