import json
import unittest

import auth


def fake_verify_jwt(*args, **kwargs):
    def dec(f):
        return f

    return dec


auth.verify_jwt = fake_verify_jwt


class PrivateKeyServerTest(unittest.TestCase):
    def setUp(self):
        from server import app
        self.app = app.test_client()
        self.token = 'not_a_token'

    def sign(self, message):
        data = self.app.post('/api/42/sign',
                             headers={"Authorization": "JWT {}".format(self.token)},
                             content_type='application/json',
                             data=json.dumps(dict(message=message))).data.decode("utf-8")
        return json.loads(data)

    def verify(self, signed):
        data = self.app.post('/api/42/verify',
                             headers={"Authorization": "JWT {}".format(self.token)},
                             content_type='application/json',
                             data=json.dumps(signed)).data.decode("utf-8")
        return json.loads(data)

    def testSigning(self):
        MESSAGE = "message"
        signed = self.sign(message=MESSAGE)
        self.assertEqual(signed["message"], MESSAGE)
        self.assertIn("signature", signed)

    def testVerification(self):
        MESSAGE = "message"
        signed = self.sign(message=MESSAGE)
        verification = self.verify(signed)
        self.assertEqual(verification["ok"], True)

    def testVerificationFailsWithWrongMessage(self):
        MESSAGE = "message"
        signed = self.sign(message=MESSAGE)
        signed["message"] = signed["message"][::-1]
        verification = self.verify(signed)
        self.assertEqual(verification["ok"], False)

    def testVerificationFailsWithWrongSignature(self):
        MESSAGE = "message"
        signed = self.sign(message=MESSAGE)
        signed["signature"] = signed["signature"][::-1]
        verification = self.verify(signed)
        self.assertEqual(verification["ok"], False)
