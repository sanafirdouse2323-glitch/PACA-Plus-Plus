from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest

from paca_service.opa import OPAClient
from paca_service.service_tokens import ClientCredentialsTokenProvider

DECISION_PATH = "/v1/data/paca/authz/decision"

pytestmark = pytest.mark.skipif(
    os.getenv("PACA_RUN_REMOTE_OPA_AUTH_INTEGRATION") != "1",
    reason="explicit authenticated remote OPA integration stage only",
)
OPA_RESOURCE = "https://opa.example.org/"


def _test_input() -> dict:
    return {
        "principal": {
            "id": "alice",
            "tenant_id": "t1",
            "roles": [],
            "scopes": ["file:read"],
            "tools": [],
        },
        "action": "file.read",
        "resource": {
            "id": "f1",
            "tenant_id": "t1",
            "owner_id": "alice",
            "kind": "file",
            "status": "active",
            "attributes": {},
        },
        "arguments": {},
    }


def test_remote_opa_authenticates_resource_bound_service_jwt_and_denies_bypasses():
    base_url = os.environ["PACA_TEST_REMOTE_OPA_URL"].rstrip("/")
    auth_dir = Path(os.environ["PACA_TEST_REMOTE_OPA_AUTH_DIR"])
    valid_token = (auth_dir / "valid.jwt").read_text(encoding="utf-8").strip()
    wrong_audience = (auth_dir / "wrong-audience.jwt").read_text(encoding="utf-8").strip()
    wrong_client = (auth_dir / "wrong-client.jwt").read_text(encoding="utf-8").strip()
    wrong_scope = (auth_dir / "wrong-scope.jwt").read_text(encoding="utf-8").strip()

    ca_file = os.environ["PACA_TEST_REMOTE_OPA_CA_FILE"]
    raw_client = httpx.Client(
        verify=ca_file,
        follow_redirects=False,
        trust_env=False,
        timeout=3,
    )
    try:
        # OPA itself must reject anonymous, wrong-audience, wrong-client and wrong-scope
        # requests before evaluating the application decision endpoint.
        anonymous = raw_client.post(
            base_url + DECISION_PATH, json={"input": _test_input()}
        )
        assert anonymous.status_code == 401, anonymous.text

        for token in (wrong_audience, wrong_client, wrong_scope):
            denied = raw_client.post(
                base_url + DECISION_PATH,
                headers={"Authorization": f"Bearer {token}"},
                json={"input": _test_input()},
            )
            assert denied.status_code == 401, denied.text

        wrong_path = raw_client.get(
            base_url + "/v1/status",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert wrong_path.status_code == 401, wrong_path.text
    finally:
        raw_client.close()

    observed_forms = []

    def token_endpoint(request: httpx.Request) -> httpx.Response:
        observed_forms.append(dict(httpx.QueryParams(request.content.decode("utf-8"))))
        return httpx.Response(
            200,
            json={
                "access_token": valid_token,
                "token_type": "Bearer",
                "expires_in": 300,
            },
        )

    oauth_http = httpx.Client(transport=httpx.MockTransport(token_endpoint))
    provider = ClientCredentialsTokenProvider(
        "https://identity.example.org/oauth/token",
        "paca-opa-client",
        "integration-test-only-secret",
        scope="opa.decide",
        resource=OPA_RESOURCE,
        client=oauth_http,
    )
    opa_http = httpx.Client(
        verify=ca_file,
        follow_redirects=False,
        trust_env=False,
        timeout=3,
    )
    client = OPAClient(
        base_url,
        DECISION_PATH,
        expected_policy_revision="paca-dev-2026-10-23",
        timeout_seconds=3,
        client=opa_http,
        token_provider=provider,
    )
    try:
        decision = client.evaluate(_test_input())
        assert decision.allowed is True, decision
        assert decision.policy_revision == "paca-dev-2026-10-23"
        assert observed_forms == [
            {
                "grant_type": "client_credentials",
                "scope": "opa.decide",
                "resource": OPA_RESOURCE,
            }
        ]
    finally:
        client.close()
        oauth_http.close()
