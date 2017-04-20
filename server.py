import os

import bitcoin as b
from uuid import UUID
from ethereum.utils import int_to_big_endian, privtopub, sha3
from flask import Flask, jsonify, request
from flask_cors import CORS

import auth

app = Flask(__name__)
app.config.from_pyfile('config.py')
app.config.from_mapping(os.environ)
CORS(app)

for key in app.config["REQUIRED_ENV_CONFIG_FIELDS"]:
    if key not in os.environ:
        raise EnvironmentError("Required env variable {} missing".format(key))

master_entropy = bytes.fromhex(app.config["MASTER_ENTROPY"])


def _user_private_key(uuid):
    user_entropy = UUID(uuid).bytes
    return sha3(b'%b%b' % (user_entropy, master_entropy))[:32]


def _user_public_key(uuid):
    user_private_key = _user_private_key(uuid)
    return privtopub(user_private_key)


def _user_address(uuid):
    public_key = _user_public_key(uuid)
    return "0x" + sha3(public_key[1:])[12:].hex()


@app.route('/api/address', methods=['GET'])
@auth.verify_jwt(check=auth.verify_logged_in)
def get_address():
    return _user_address(request.authorization["uuid"])


@app.route('/api/sign', methods=['POST'])
@auth.verify_jwt(check=auth.verify_logged_in)
def sign_message_by_user():
    user_private_key = _user_private_key(request.authorization["uuid"])
    message = bytes.fromhex(request.get_json()["message"])
    digest = sha3(message)
    v, r, s = b.ecdsa_raw_sign(digest, user_private_key)
    return jsonify({
        "v": int_to_big_endian(v).hex(),
        "r": int_to_big_endian(r).hex(),
        "s": int_to_big_endian(s).hex(),
        "message": request.get_json()["message"]
    })


@app.errorhandler(403)
def forbidden(ex):
    return jsonify({"code": 403, "message": ex.description}), 403


@app.errorhandler(404)
def not_found(ex):
    return jsonify({"code": 404, "message": ex.description}), 404


if __name__ == '__main__':
    app.run()
