import os

from ecdsa import SECP256k1, SigningKey
from flask import Flask, jsonify, request

import auth

app = Flask(__name__)
app.config.from_pyfile('config.py')

app.config.from_mapping(os.environ)


@app.route('/api/<string:uid>/sign', methods=['POST'])
@auth.verify_jwt(check=auth.verify_logged_in)
def sign_message_by_user(uid):
    message = request.get_json()["message"]
    binary_message = message.encode('utf-8')
    key = SigningKey.generate(curve=SECP256k1)
    signature = key.sign(binary_message)
    return signature.hex()


@app.errorhandler(403)
def forbidden(ex):
    return jsonify({"code": 403, "message": ex.description}), 403


@app.errorhandler(404)
def not_found(ex):
    return jsonify({"code": 404, "message": ex.description}), 404


if __name__ == '__main__':
    app.run()
