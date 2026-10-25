from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from paca_mvp.hardening import (
    AuthenticationFailed, ContextUnavailable, GuardedGateway, IdentityProviderUnavailable,
    OPAClient, PermitRejected, SQLitePermitStore, TrustedPrincipal,
)
from paca_mvp.providers import HTTPAuthorizationContextProvider, OIDCJWTIdentityProvider


class FakeResponse:
    status = 200

    def __init__(self, result):
        self.data = json.dumps(result).encode("utf-8")

    def read(self, size=-1):
        return self.data[:size]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class OIDCIdentityTests(unittest.TestCase):
    def setUp(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.now = int(time.time())
        self.provider = OIDCJWTIdentityProvider(
            issuer="https://issuer.example", audience="paca-api",
            jwks_url="https://issuer.example/.well-known/jwks.json",
        )

    def token(self, key=None, **overrides):
        claims = {
            "iss": "https://issuer.example", "aud": "paca-api",
            "sub": "user-17", "iat": self.now, "exp": self.now + 120,
            "role": "analyst", "suspended": False,
        }
        claims.update(overrides)
        return jwt.encode(claims, key or self.private_key, algorithm="RS256",
                          headers={"kid": "test-key"})

    def test_valid_rs256_signature_issuer_audience_and_expiry(self):
        public_key = self.public_key

        class SigningKey:
            key = public_key

        class FakeJWKClient:
            def get_signing_key_from_jwt(self, token):
                return SigningKey()

        with patch("jwt.PyJWKClient", return_value=FakeJWKClient()):
            principal = self.provider.authenticate(self.token())
        self.assertEqual(principal.subject, "user-17")
        self.assertEqual(principal.issuer, "https://issuer.example")
        self.assertEqual(principal.claims["role"], "analyst")

    def test_wrong_issuer_audience_signature_and_algorithm_fail_closed(self):
        public_key = self.public_key

        class SigningKey:
            key = public_key

        class FakeJWKClient:
            def get_signing_key_from_jwt(self, token):
                return SigningKey()

        with patch("jwt.PyJWKClient", return_value=FakeJWKClient()):
            with self.assertRaises(AuthenticationFailed):
                self.provider.authenticate(self.token(iss="https://attacker.example"))
            with self.assertRaises(AuthenticationFailed):
                self.provider.authenticate(self.token(aud="different-api"))
            other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            with self.assertRaises(AuthenticationFailed):
                self.provider.authenticate(self.token(key=other_key))
            bad_algorithm = jwt.encode(
                {"iss": "https://issuer.example", "aud": "paca-api", "sub": "user-17",
                 "iat": self.now, "exp": self.now + 120},
                "test-only-hmac-key-that-is-long-enough-for-hs256", algorithm="HS256", headers={"kid": "test-key"},
            )
            with self.assertRaises(AuthenticationFailed):
                self.provider.authenticate(bad_algorithm)

    def test_jwks_connection_failure_is_an_identity_provider_outage(self):
        class UnavailableJWKClient:
            def get_signing_key_from_jwt(self, token):
                raise jwt.exceptions.PyJWKClientConnectionError("test network outage")

        with patch("jwt.PyJWKClient", return_value=UnavailableJWKClient()):
            with self.assertRaises(IdentityProviderUnavailable):
                self.provider.authenticate(self.token())

    def test_non_https_issuer_is_rejected_at_configuration_time(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            OIDCJWTIdentityProvider(
                issuer="http://issuer.example", audience="paca-api",
                jwks_url="https://issuer.example/.well-known/jwks.json",
            )

    def test_malformed_credential_fails_closed(self):
        with self.assertRaises(AuthenticationFailed):
            self.provider.authenticate("not.a.jwt")


class IdentityProviderGatewayTests(unittest.TestCase):
    def test_jwks_outage_is_audited_and_propagated_without_becoming_401(self):
        with tempfile.TemporaryDirectory() as temp:
            store = SQLitePermitStore(str(Path(temp) / "paca.sqlite3"))

            class UnavailableIdentityProvider:
                def authenticate(self, credential):
                    raise IdentityProviderUnavailable("JWKS service unavailable")

            gateway = GuardedGateway(object(), store, UnavailableIdentityProvider(), object())
            with self.assertRaises(IdentityProviderUnavailable):
                gateway.authorize_and_execute(
                    "bearer", "file.read", "file:report-1", {},
                    object(), "idempotency-jwks-outage",
                )
            events = store.audit_events()
            self.assertEqual(events[-1]["event"], "identity_provider_unavailable")
            self.assertNotIn("bearer", json.dumps(events))


class TrustedContextTests(unittest.TestCase):
    def test_context_retrieval_is_authenticated_and_cannot_forge_identity(self):
        principal = TrustedPrincipal(
            "user-17", "https://issuer.example", "paca-api",
            {"role": "analyst"}, "2026-01-01T00:00:00+00:00",
        )
        provider = HTTPAuthorizationContextProvider(
            "https://context.example/v1/attributes", "service-token-" + "x" * 20
        )
        with patch("paca_mvp.providers._urlopen_no_redirect",
                   return_value=FakeResponse({"authorization": {"role": "analyst"}})) as mocked:
            result = provider.get_context(principal, "file.read", "file:report-1")
        self.assertEqual(result, {"authorization": {"role": "analyst"}})
        req = mocked.call_args.args[0]
        self.assertEqual(req.full_url, "https://context.example/v1/attributes")
        self.assertEqual(req.get_header("Authorization"), "Bearer " + "service-token-" + "x" * 20)
        self.assertEqual(json.loads(req.data.decode())["subject"], "user-17")

        with patch("paca_mvp.providers._urlopen_no_redirect",
                   return_value=FakeResponse({"identity": {"subject": "attacker"}})):
            with self.assertRaises(ContextUnavailable):
                provider.get_context(principal, "file.read", "file:report-1")


class PolicyRolloverTests(unittest.TestCase):
    def test_active_policy_version_change_blocks_effect(self):
        with tempfile.TemporaryDirectory() as temp:
            store = SQLitePermitStore(str(Path(temp) / "paca.sqlite3"))
            principal = TrustedPrincipal(
                "user-17", "https://issuer.example", "paca-api",
                {"sub": "user-17", "role": "analyst", "suspended": False},
                "2026-01-01T00:00:00+00:00",
            )
            class IdP:
                def authenticate(self, credential):
                    return principal
            class Context:
                def get_context(self, *args):
                    return {"authorization": {"role": "analyst"},
                            "resource": {"owner": "user-17"}}
            class OPA:
                def decide(self, request):
                    return {"allowed": True, "policy_version": "v1", "reason": "permitted"}
                def get_policy_version(self):
                    return "v2"
            class Adapter:
                called = False
                def invoke(self, *args):
                    self.called = True
                    return {"unsafe": True}
            adapter = Adapter()
            gateway = GuardedGateway(OPA(), store, IdP(), Context())
            with self.assertRaisesRegex(PermitRejected, "stale policy"):
                gateway.authorize_and_execute("credential", "file.write", "file:report-1",
                                              {"content": "x"}, adapter, "idem-version")
            self.assertFalse(adapter.called)


if __name__ == "__main__":
    unittest.main()
