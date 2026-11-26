import base64
import hashlib
import json
import time
import unittest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
from paca_service.dpop import DPoPValidator, DPoPVerificationError

class DPoPValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = DPoPValidator(max_clock_skew_seconds=60.0)
        # Generate test RSA private key
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()
        
        # Build JWK representation
        public_numbers = cls.public_key.public_numbers()
        e_bytes = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')
        n_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')
        cls.jwk = {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "e": base64.urlsafe_b64encode(e_bytes).decode('utf-8').rstrip('='),
            "n": base64.urlsafe_b64encode(n_bytes).decode('utf-8').rstrip('='),
        }

    def _create_dpop_proof(self, htm="POST", htu="http://127.0.0.1:8000/v1/authorizations", iat=None, access_token=None):
        if iat is None:
            iat = int(time.time())
        payload = {
            "jti": f"proof-{time.time()}",
            "htm": htm,
            "htu": htu,
            "iat": iat,
        }
        if access_token:
            payload["ath"] = self.validator.compute_ath(access_token)
            
        headers = {
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": self.jwk
        }
        return jwt.encode(payload, self.private_key, algorithm="RS256", headers=headers)

    def test_valid_dpop_proof(self):
        token = "test-access-token-12345"
        proof = self._create_dpop_proof(access_token=token)
        payload = self.validator.verify_dpop_proof(
            dpop_header=proof,
            http_method="POST",
            http_url="http://127.0.0.1:8000/v1/authorizations",
            access_token=token
        )
        self.assertEqual(payload["htm"], "POST")

    def test_method_mismatch_rejected(self):
        proof = self._create_dpop_proof(htm="GET")
        with self.assertRaises(DPoPVerificationError) as ctx:
            self.validator.verify_dpop_proof(
                dpop_header=proof,
                http_method="POST",
                http_url="http://127.0.0.1:8000/v1/authorizations"
            )
        self.assertEqual(str(ctx.exception), "dpop_htm_mismatch")

    def test_uri_mismatch_rejected(self):
        proof = self._create_dpop_proof(htu="http://127.0.0.1:8000/v1/executions")
        with self.assertRaises(DPoPVerificationError) as ctx:
            self.validator.verify_dpop_proof(
                dpop_header=proof,
                http_method="POST",
                http_url="http://127.0.0.1:8000/v1/authorizations"
            )
        self.assertEqual(str(ctx.exception), "dpop_htu_mismatch")

    def test_token_hash_mismatch_rejected(self):
        proof = self._create_dpop_proof(access_token="token-A")
        with self.assertRaises(DPoPVerificationError) as ctx:
            self.validator.verify_dpop_proof(
                dpop_header=proof,
                http_method="POST",
                http_url="http://127.0.0.1:8000/v1/authorizations",
                access_token="token-B"
            )
        self.assertEqual(str(ctx.exception), "dpop_ath_mismatch")

    def test_expired_proof_rejected(self):
        proof = self._create_dpop_proof(iat=int(time.time()) - 120)
        with self.assertRaises(DPoPVerificationError) as ctx:
            self.validator.verify_dpop_proof(
                dpop_header=proof,
                http_method="POST",
                http_url="http://127.0.0.1:8000/v1/authorizations"
            )
        self.assertEqual(str(ctx.exception), "dpop_proof_expired_or_future")

if __name__ == "__main__":
    unittest.main()
