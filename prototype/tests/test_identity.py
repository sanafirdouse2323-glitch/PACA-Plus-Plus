from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from paca_mvp.identity import (
    AuthenticationError,
    AuthenticatedPrincipal,
    CallbackContextProvider,
    ContextRetrievalError,
    JWTAuthenticator,
)


class JWTAuthenticatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.issuer = "https://identity.example"
        cls.audience = "paca-test-api"
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()
        cls.authenticator = JWTAuthenticator(
            issuer=cls.issuer,
            audience=cls.audience,
            key_resolver=lambda _token: cls.public_key,
        )

    def token(self, **overrides):
        now = int(datetime.now(timezone.utc).timestamp())
        payload = {
            "iss": self.issuer,
            "sub": "user-42",
            "aud": self.audience,
            "iat": now,
            "exp": now + 60,
        }
        payload.update(overrides)
        return jwt.encode(payload, self.private_key, algorithm="RS256")

    def authenticate(self, token):
        return self.authenticator.authenticate("Bearer " + token)

    def test_accepts_valid_token_and_scopes_storage_id_to_issuer_and_subject(self):
        principal = self.authenticate(self.token())
        self.assertEqual(principal.subject, "user-42")
        self.assertEqual(principal.issuer, self.issuer)
        self.assertEqual(principal.opa_identity(), {"id": principal.storage_id, "issuer": self.issuer})
        self.assertTrue(principal.storage_id.startswith("oidc:"))
        self.assertNotEqual(principal.storage_id, principal.subject)

    def test_same_subject_under_different_issuers_has_different_policy_identity(self):
        first = AuthenticatedPrincipal("same-subject", self.issuer, {"sub": "same-subject"})
        second = AuthenticatedPrincipal("same-subject", "https://another-identity.example", {"sub": "same-subject"})
        self.assertNotEqual(first.storage_id, second.storage_id)
        self.assertNotEqual(first.opa_identity()["id"], second.opa_identity()["id"])
        self.assertEqual(first.subject, second.subject)
        self.assertNotIn("subject", first.opa_identity())

    def test_rejects_signature_from_untrusted_key(self):
        now = int(datetime.now(timezone.utc).timestamp())
        token = jwt.encode(
            {"iss": self.issuer, "sub": "user-42", "aud": self.audience,
             "iat": now, "exp": now + 60},
            self.other_private_key,
            algorithm="RS256",
        )
        with self.assertRaises(AuthenticationError):
            self.authenticate(token)

    def test_rejects_wrong_issuer(self):
        with self.assertRaises(AuthenticationError):
            self.authenticate(self.token(iss="https://attacker.example"))

    def test_rejects_wrong_audience(self):
        with self.assertRaises(AuthenticationError):
            self.authenticate(self.token(aud="different-api"))

    def test_rejects_expired_token(self):
        now = int(datetime.now(timezone.utc).timestamp())
        with self.assertRaises(AuthenticationError):
            self.authenticate(self.token(iat=now - 120, exp=now - 60))

    def test_requires_expiration_claim(self):
        now = int(datetime.now(timezone.utc).timestamp())
        token = jwt.encode(
            {"iss": self.issuer, "sub": "user-42", "aud": self.audience, "iat": now},
            self.private_key,
            algorithm="RS256",
        )
        with self.assertRaises(AuthenticationError):
            self.authenticate(token)

    def test_rejects_algorithm_substitution(self):
        token = jwt.encode(
            {"iss": self.issuer, "sub": "user-42", "aud": self.audience,
             "iat": int(datetime.now(timezone.utc).timestamp()),
             "exp": int((datetime.now(timezone.utc) + timedelta(minutes=1)).timestamp())},
            "this-is-a-deliberately-long-test-secret-for-hs256",
            algorithm="HS256",
        )
        with self.assertRaises(AuthenticationError):
            self.authenticate(token)

    def test_rejects_control_characters_in_subject(self):
        with self.assertRaises(AuthenticationError):
            self.authenticate(self.token(sub="user\nattacker"))

    def test_rejects_missing_bearer_header(self):
        with self.assertRaises(AuthenticationError):
            self.authenticator.authenticate(None)

    def test_rejects_issuer_configured_without_https(self):
        with self.assertRaises(ValueError):
            JWTAuthenticator(
                issuer="http://identity.example",
                audience=self.audience,
                key_resolver=lambda _token: self.public_key,
            )


class TrustedContextProviderTests(unittest.TestCase):
    def test_context_is_loaded_from_callbacks_and_snapshotted(self):
        principal = AuthenticatedPrincipal("user-42", "https://identity.example", {"sub": "user-42"})
        subject = {"status": "active", "role": "analyst", "tenant_id": "tenant-1", "user_id": "db-user-42"}
        resource = {"owner_id": "db-user-42", "tenant_id": "tenant-1", "canonical_path": "reports/q1.csv"}
        calls = []

        def subject_lookup(p):
            # The identity mapping must be keyed by both issuer and subject.
            calls.append(("subject", p.issuer, p.subject))
            return subject

        def resource_lookup(p, action, resource_id, arguments):
            calls.append(("resource", action, resource_id, dict(arguments)))
            return resource

        provider = CallbackContextProvider(subject_lookup, resource_lookup)
        context = provider.load(principal, "file.read", "file:r1", {"path": "reports/q1.csv"})

        subject["role"] = "admin"
        resource["canonical_path"] = "secrets.csv"
        self.assertEqual(context.subject_attributes["role"], "analyst")
        self.assertEqual(context.resource_attributes["canonical_path"], "reports/q1.csv")
        self.assertEqual(calls, [
            ("subject", "https://identity.example", "user-42"),
            ("resource", "file.read", "file:r1", {"path": "reports/q1.csv"}),
        ])

    def test_non_finite_context_is_rejected(self):
        principal = AuthenticatedPrincipal("user-42", "https://identity.example", {"sub": "user-42"})
        provider = CallbackContextProvider(
            lambda _p: {"status": "active", "score": float("nan")},
            lambda _p, _a, _r, _args: {"owner_id": "db-user-42"},
        )
        with self.assertRaises(ContextRetrievalError):
            provider.load(principal, "file.read", "file:r1", {})


if __name__ == "__main__":
    unittest.main()
