from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest
from jwt.exceptions import PyJWKClientConnectionError

from paca_service.auth import (
    AuthenticationError,
    IdentityProviderUnavailable,
    JWTAuthenticator,
)
from paca_service.opa import OPAClient, PolicyEngineUnavailable


ISSUER = "https://identity.example.org/"
AUDIENCE = "paca-api"


class FakeJWKS:
    def __init__(self, key):
        self.key = key

    def get_signing_key_from_jwt(self, token: str):
        return SimpleNamespace(key=self.key)


def signed_token(private_key, **overrides):
    now = datetime.now(timezone.utc)
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "alice",
        "tenant_id": "tenant-1",
        "roles": ["analyst"],
        "scope": "file:read tool:invoke",
        "tools": ["text.word_count"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "jti": "jwt-123",
    }
    payload.update(overrides)
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key"})


@pytest.fixture
def rsa_keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


def test_authenticator_verifies_signature_issuer_audience_and_required_claims(rsa_keys):
    private, public = rsa_keys
    auth = JWTAuthenticator(ISSUER, AUDIENCE, "https://identity.example.org/jwks", jwks_client=FakeJWKS(public))
    principal = auth.authenticate(signed_token(private))
    assert principal.subject == "alice"
    assert principal.tenant_id == "tenant-1"
    assert principal.roles == ("analyst",)
    assert principal.scopes == ("file:read", "tool:invoke")
    assert principal.tools == ("text.word_count",)
    assert principal.token_id == "jwt-123"

    with pytest.raises(AuthenticationError):
        auth.authenticate(signed_token(private, iss="https://attacker.example/"))
    with pytest.raises(AuthenticationError):
        auth.authenticate(signed_token(private, aud="another-api"))
    with pytest.raises(AuthenticationError):
        auth.authenticate(signed_token(private, tenant_id=""))


def test_authenticator_pins_rs256_and_rejects_unsigned_or_hmac_tokens(rsa_keys):
    private, public = rsa_keys
    auth = JWTAuthenticator(ISSUER, AUDIENCE, "https://identity.example.org/jwks", jwks_client=FakeJWKS(public))
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "iss": ISSUER, "aud": AUDIENCE, "sub": "alice", "tenant_id": "tenant-1",
            "iat": int(now.timestamp()), "exp": int((now + timedelta(minutes=5)).timestamp()),
        },
        "not-a-real-rsa-key",
        algorithm="HS256",
    )
    with pytest.raises(AuthenticationError):
        auth.authenticate(token)


def test_authenticator_fails_with_service_unavailable_when_jwks_is_unreachable():
    class OfflineJWKS:
        def get_signing_key_from_jwt(self, token: str):
            raise PyJWKClientConnectionError("offline")

    auth = JWTAuthenticator(ISSUER, AUDIENCE, "https://identity.example.org/jwks", jwks_client=OfflineJWKS())
    with pytest.raises(IdentityProviderUnavailable):
        auth.authenticate("a.valid-looking-but-unchecked.token")


def opa_client(handler, expected="paca-dev-2026-10-23"):
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return OPAClient(
        "http://opa:8181",
        "/v1/data/paca/authz/decision",
        expected,
        timeout_seconds=1,
        client=client,
    )


def test_opa_named_decision_result_is_parsed_with_decision_id():
    client = opa_client(lambda req: httpx.Response(
        200, json={"result": {"allow": True, "reason": "ok", "policy_revision": "paca-dev-2026-10-23"},
                   "decision_id": "decision-1"}
    ))
    decision = client.evaluate({"action": "document.read"})
    assert decision.allowed is True
    assert decision.decision_id == "decision-1"
    client.close()


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"result": True},
        {"result": {"allow": "true", "reason": "bad", "policy_revision": "paca-dev-2026-10-23"}},
        {"result": {"allow": True, "reason": "ok"}},
        {"result": {"allow": True, "reason": "ok", "policy_revision": "wrong-revision"}},
    ],
)
def test_opa_undefined_or_malformed_decision_fails_closed(body):
    client = opa_client(lambda req: httpx.Response(200, json=body))
    with pytest.raises(PolicyEngineUnavailable):
        client.evaluate({"action": "document.read"})
    client.close()


def test_opa_http_error_and_network_error_fail_closed():
    client = opa_client(lambda req: httpx.Response(404, json={"error": "undefined"}))
    with pytest.raises(PolicyEngineUnavailable):
        client.evaluate({"action": "document.read"})
    client.close()

    def network_error(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=req)
    client = opa_client(network_error)
    with pytest.raises(PolicyEngineUnavailable):
        client.evaluate({"action": "document.read"})
    client.close()
