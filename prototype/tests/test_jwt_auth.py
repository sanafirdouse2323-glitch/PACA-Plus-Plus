from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import datetime
import unittest

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    jwt = None
    rsa = None

from paca_mvp.identity import AuthenticationError, JWTAuthenticator


@unittest.skipIf(jwt is None, "Install the production extra to test PyJWT signature verification")
class JWTAuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()

    def setUp(self):
        self.authenticator = JWTAuthenticator(
            issuer="https://issuer.example",
            audience="paca-test",
            algorithms=("RS256",),
            key_resolver=lambda _token: self.public_key,
        )

    def make_token(self, **overrides):
        now = datetime.datetime.now(datetime.timezone.utc)
        claims = {
            "iss": "https://issuer.example",
            "aud": "paca-test",
            "sub": "user-1",
            "iat": int(now.timestamp()),
            "exp": int((now + datetime.timedelta(minutes=3)).timestamp()),
        }
        claims.update(overrides)
        return jwt.encode(claims, self.private_key, algorithm="RS256")

    def test_valid_token_produces_only_verified_principal_identity(self):
        token = self.make_token(email="private@example.com", groups=["analysts"])
        principal = self.authenticator.authenticate("Bearer " + token)
        self.assertEqual(principal.subject, "user-1")
        self.assertEqual(principal.issuer, "https://issuer.example")
        self.assertEqual(principal.opa_identity(), {
            "id": principal.storage_id,
            "issuer": "https://issuer.example",
        })
        self.assertNotIn("subject", principal.opa_identity())

    def test_wrong_issuer_is_rejected(self):
        token = self.make_token(iss="https://attacker.example")
        with self.assertRaises(AuthenticationError):
            self.authenticator.authenticate("Bearer " + token)

    def test_wrong_audience_is_rejected(self):
        token = self.make_token(aud="different-service")
        with self.assertRaises(AuthenticationError):
            self.authenticator.authenticate("Bearer " + token)

    def test_expired_token_is_rejected(self):
        past = int((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)).timestamp())
        token = self.make_token(exp=past)
        with self.assertRaises(AuthenticationError):
            self.authenticator.authenticate("Bearer " + token)

    def test_unsigned_or_wrong_signature_token_is_rejected(self):
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        claims = {
            "iss": "https://issuer.example", "aud": "paca-test", "sub": "user-1",
            "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
            "exp": int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=3)).timestamp()),
        }
        token = jwt.encode(claims, other_key, algorithm="RS256")
        with self.assertRaises(AuthenticationError):
            self.authenticator.authenticate("Bearer " + token)

    def test_missing_bearer_header_is_rejected(self):
        with self.assertRaises(AuthenticationError):
            self.authenticator.authenticate(None)


    def test_insecure_issuer_url_is_rejected_at_configuration(self):
        with self.assertRaises(ValueError):
            JWTAuthenticator(
                issuer="http://issuer.example",
                audience="paca-test",
                algorithms=("RS256",),
                key_resolver=lambda _token: self.public_key,
            )


    def test_storage_identity_is_scoped_to_issuer_and_subject_without_exposing_them(self):
        principal = self.authenticator.authenticate("Bearer " + self.make_token())
        another_issuer = type(principal)(
            subject=principal.subject,
            issuer="https://second-issuer.example",
            claims=principal.claims,
        )
        another_subject = type(principal)(
            subject="user-2",
            issuer=principal.issuer,
            claims={"sub": "user-2"},
        )
        self.assertTrue(principal.storage_id.startswith("oidc:"))
        self.assertNotIn(principal.subject, principal.storage_id)
        self.assertNotEqual(principal.storage_id, another_issuer.storage_id)
        self.assertNotEqual(principal.storage_id, another_subject.storage_id)
        self.assertEqual(principal.storage_id, type(principal)(
            subject=principal.subject, issuer=principal.issuer, claims=principal.claims
        ).storage_id)


if __name__ == "__main__":
    unittest.main()
