import os

from bip32utils import BIP32Key
from ethereum.utils import sha3
from flask import Flask, jsonify, request

import auth

app = Flask(__name__)
app.config.from_pyfile('config.py')

app.config.from_mapping(os.environ)

entropy = os.urandom(32)
masterPrivateKey = BIP32Key.fromEntropy(entropy)


def pub_to_addr(pub):
    assert (len(pub) == 64)
    return sha3(pub)[12:]


@app.route('/api/<int:uid>/sign', methods=['POST'])
@auth.verify_jwt(check=auth.verify_logged_in)
def sign_message_by_user(uid):
    message = request.get_json()["message"]
    binary_message = message.encode('utf-8')
    childPrivateKey = masterPrivateKey.ChildKey(uid)
    signature = childPrivateKey.k.sign(binary_message).hex()
    return jsonify({
        "signature": signature,
        "message": message
    })


@app.route('/api/<int:uid>/verify', methods=['POST'])
def verify_signed_message(uid):
    data = request.get_json()
    verifying_key = masterPrivateKey.ChildKey(uid).K
    signature = bytes.fromhex(data["signature"])
    message = data["message"].encode('utf-8')
    return jsonify({"ok": verifying_key.verify(signature, message)})


@app.errorhandler(403)
def forbidden(ex):
    return jsonify({"code": 403, "message": ex.description}), 403


@app.errorhandler(404)
def not_found(ex):
    return jsonify({"code": 404, "message": ex.description}), 404


if __name__ == '__main__':
    app.run()
