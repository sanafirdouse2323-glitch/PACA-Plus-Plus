from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
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


def signed_token(private_key, kid: str = "test-key", omit_claim: str | None = None, **overrides):
    now = datetime.now(UTC)
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
    if omit_claim is not None:
        payload.pop(omit_claim, None)
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})



def public_jwk(public_key, kid: str) -> dict[str, object]:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return jwk


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



@pytest.mark.parametrize("missing_claim", ["sub", "exp", "iat", "iss", "aud", "tenant_id"])
def test_authenticator_requires_identity_claims(rsa_keys, missing_claim):
    private, public = rsa_keys
    auth = JWTAuthenticator(
        ISSUER,
        AUDIENCE,
        "https://identity.example.org/jwks",
        jwks_client=FakeJWKS(public),
    )
    with pytest.raises(AuthenticationError):
        auth.authenticate(signed_token(private, omit_claim=missing_claim))


@pytest.mark.parametrize(
    "claims",
    [
        {"sub": ""},
        {"sub": 42},
        {"tenant_id": 7},
        {"tenant_id": "   "},
        {"roles": "admin"},
        {"roles": [7]},
        {"tools": [" "]},
        {"scopes": 7},
    ],
)
def test_authenticator_rejects_malformed_identity_and_authorization_claims(rsa_keys, claims):
    private, public = rsa_keys
    auth = JWTAuthenticator(
        ISSUER,
        AUDIENCE,
        "https://identity.example.org/jwks",
        jwks_client=FakeJWKS(public),
    )
    with pytest.raises(AuthenticationError):
        auth.authenticate(signed_token(private, **claims))


def test_authenticator_refreshes_jwks_when_provider_rotates_to_a_new_kid(monkeypatch):
    old_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    published = {"keys": [public_jwk(old_private.public_key(), "key-1")]}
    fetch_count = 0

    jwks_client = jwt.PyJWKClient(
        "https://identity.example.org/jwks",
        cache_jwk_set=True,
        lifespan=300,
        timeout=1,
        cooldown_duration=30,
    )

    def fetch_data():
        nonlocal fetch_count
        fetch_count += 1
        return published

    monkeypatch.setattr(jwks_client, "fetch_data", fetch_data)
    auth = JWTAuthenticator(
        ISSUER,
        AUDIENCE,
        "https://identity.example.org/jwks",
        jwks_client=jwks_client,
    )

    old_principal = auth.authenticate(signed_token(old_private, kid="key-1"))
    assert old_principal.subject == "alice"
    assert fetch_count == 1

    # Simulate the provider publishing a rotated public key with a new, unique kid.
    published["keys"] = [public_jwk(new_private.public_key(), "key-2")]
    new_principal = auth.authenticate(signed_token(new_private, kid="key-2"))
    assert new_principal.subject == "alice"
    assert fetch_count == 2


def test_authenticator_pins_rs256_and_rejects_unsigned_or_hmac_tokens(rsa_keys):
    _private, public = rsa_keys
    auth = JWTAuthenticator(ISSUER, AUDIENCE, "https://identity.example.org/jwks", jwks_client=FakeJWKS(public))
    now = datetime.now(UTC)
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
