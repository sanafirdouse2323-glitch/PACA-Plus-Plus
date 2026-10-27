from __future__ import annotations

import os
import uuid
from pathlib import Path
from urllib.parse import urljoin

import httpx
import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from paca_service.adapters import AdapterRouter, SandboxedFileAdapter
from paca_service.app import create_app
from paca_service.auth import AuthenticationError, JWTAuthenticator
from paca_service.config import Settings
from paca_service.opa import OPAClient
from paca_service.store import PostgresStore

REALM_URL = os.getenv("PACA_TEST_OIDC_REALM_URL", "").rstrip("/")
DATABASE_URL = os.getenv("PACA_TEST_DATABASE_URL", "")
ADMIN_DATABASE_URL = os.getenv("PACA_TEST_ADMIN_DATABASE_URL", "")
OPA_URL = os.getenv("PACA_TEST_OPA_URL", "http://127.0.0.1:8181").rstrip("/")
POLICY_REVISION = "paca-dev-2026-10-23"
CLIENT_ID = "paca-api"
USERNAME = "paca-e2e-user"
PASSWORD = "paca-e2e-only-password"


def _password_token(token_endpoint: str, client_id: str, username: str) -> str:
    response = httpx.post(
        token_endpoint,
        data={
            "grant_type": "password",
            "client_id": client_id,
            "username": username,
            "password": PASSWORD,
            "scope": "openid",
        },
        timeout=10.0,
        follow_redirects=False,
        trust_env=False,
    )
    assert response.status_code == 200, (
        f"OIDC token endpoint rejected the integration test client/user: "
        f"HTTP {response.status_code}: {response.text}"
    )
    token = response.json().get("access_token")
    assert isinstance(token, str) and token
    return token


@pytest.mark.skipif(
    not (REALM_URL and DATABASE_URL and ADMIN_DATABASE_URL),
    reason=(
        "set PACA_TEST_OIDC_REALM_URL and PostgreSQL test DSNs to run "
        "the real OIDC/PostgreSQL/OPA end-to-end flow"
    ),
)
def test_keycloak_oidc_token_runs_the_real_authorization_and_execution_flow(
    tmp_path: Path,
) -> None:
    # Read the provider's OIDC metadata instead of deriving issuer/JWKS URLs from
    # assumptions. The exact metadata issuer is then the issuer expected by JWT validation.
    discovery_url = urljoin(REALM_URL + "/", ".well-known/openid-configuration")
    metadata_response = httpx.get(
        discovery_url, timeout=10.0, follow_redirects=False, trust_env=False
    )
    assert metadata_response.status_code == 200, metadata_response.text
    metadata = metadata_response.json()
    assert metadata.get("issuer") == REALM_URL, (
        f"OIDC discovery issuer mismatch: expected {REALM_URL!r}, "
        f"received {metadata.get('issuer')!r}"
    )
    token_endpoint = metadata.get("token_endpoint")
    jwks_uri = metadata.get("jwks_uri")
    assert isinstance(token_endpoint, str) and token_endpoint
    assert isinstance(jwks_uri, str) and jwks_uri

    token = _password_token(token_endpoint, CLIENT_ID, USERNAME)
    authenticator = JWTAuthenticator(
        issuer=metadata["issuer"],
        audience=CLIENT_ID,
        jwks_url=jwks_uri,
        timeout_seconds=5.0,
    )
    principal = authenticator.authenticate(token)
    assert principal.tenant_id == "tenant-e2e"
    assert "file:read" in principal.scopes
    assert principal.subject

    # A real token from a different client audience must not authenticate to PACA.
    wrong_audience_token = _password_token(
        token_endpoint, "wrong-audience-client", USERNAME
    )
    with pytest.raises(AuthenticationError):
        authenticator.authenticate(wrong_audience_token)

    other_tenant_token = _password_token(
        token_endpoint, CLIENT_ID, "paca-other-user"
    )
    other_principal = authenticator.authenticate(other_tenant_token)
    assert other_principal.tenant_id == "tenant-other"
    assert other_principal.subject != principal.subject

    resource_id = "oidc-e2e-" + uuid.uuid4().hex
    denied_resource_id = resource_id + "-wrong-owner"
    relative_path = "oidc-e2e-" + uuid.uuid4().hex + ".txt"
    content = "The real OIDC provider issued this protected resource access."
    target = tmp_path / relative_path
    target.write_text(content, encoding="utf-8")
    resource_attributes = {"relative_path": relative_path}

    # Provision fixture facts only through the separate database admin connection.
    with psycopg.connect(ADMIN_DATABASE_URL, row_factory=dict_row) as admin:
        admin.execute(
            """
            INSERT INTO protected_resources
                (tenant_id, resource_id, owner_id, kind, status, attributes)
            VALUES (%s, %s, %s, 'file', 'active', %s)
            """,
            (principal.tenant_id, resource_id, principal.subject, Jsonb(resource_attributes)),
        )
        admin.execute(
            """
            INSERT INTO protected_resources
                (tenant_id, resource_id, owner_id, kind, status, attributes)
            VALUES (%s, %s, %s, 'file', 'active', %s)
            """,
            (
                principal.tenant_id, denied_resource_id, "not-" + principal.subject,
                Jsonb({"relative_path": relative_path}),
            ),
        )

    store = PostgresStore(DATABASE_URL)
    opa = OPAClient(
        OPA_URL,
        "/v1/data/paca/authz/decision",
        POLICY_REVISION,
        timeout_seconds=2.0,
    )
    settings = Settings(
        database_url=DATABASE_URL,
        opa_url=OPA_URL,
        opa_decision_path="/v1/data/paca/authz/decision",
        opa_timeout_seconds=2.0,
        expected_policy_revision=POLICY_REVISION,
        jwt_issuer=metadata["issuer"],
        jwt_audience=CLIENT_ID,
        jwt_jwks_url=jwks_uri,
        jwt_timeout_seconds=5.0,
        permit_ttl_seconds=30,
        execution_timeout_seconds=10.0,
        stale_execution_seconds=120,
        api_base_url=None,
        api_routes={},
        api_bearer_token=None,
        file_root=str(tmp_path),
    )
    app = create_app(
        settings=settings,
        store=store,
        opa=opa,
        authenticator=authenticator,
        adapter_router=AdapterRouter([SandboxedFileAdapter(str(tmp_path))]),
    )

    try:
        with TestClient(app) as client:
            auth_headers = {"Authorization": f"Bearer {token}"}

            unauthorized = client.post(
                "/v1/authorizations",
                headers={"Authorization": f"Bearer {wrong_audience_token}"},
                json={"action": "file.read", "resource_id": resource_id, "arguments": {}},
            )
            assert unauthorized.status_code == 401, unauthorized.text

            cross_tenant = client.post(
                "/v1/authorizations",
                headers={"Authorization": f"Bearer {other_tenant_token}"},
                json={"action": "file.read", "resource_id": resource_id, "arguments": {}},
            )
            assert cross_tenant.status_code == 404, cross_tenant.text

            # Real provider token -> trusted PostgreSQL resource -> live OPA decision -> permit.
            authorization = client.post(
                "/v1/authorizations",
                headers=auth_headers,
                json={"action": "file.read", "resource_id": resource_id, "arguments": {}},
            )
            assert authorization.status_code == 201, authorization.text
            permit_id = authorization.json()["permit_id"]
            assert authorization.json()["policy_revision"] == POLICY_REVISION

            # Execute the permit against the real sandboxed file adapter and persistent PostgreSQL store.
            execution = client.post(
                "/v1/executions",
                headers={**auth_headers, "Idempotency-Key": "oidc-e2e-" + uuid.uuid4().hex},
                json={
                    "permit_id": permit_id,
                    "action": "file.read",
                    "resource_id": resource_id,
                    "arguments": {},
                },
            )
            assert execution.status_code == 200, execution.text
            result = execution.json()
            assert result["status"] == "succeeded"
            assert result["result"]["content"] == content
            execution_id = result["execution_id"]

            # The persistent execution status route uses the same real authenticated identity.
            status = client.get(
                f"/v1/executions/{execution_id}",
                headers=auth_headers,
            )
            assert status.status_code == 200, status.text
            assert status.json()["status"] == "succeeded"

            cross_tenant_status = client.get(
                f"/v1/executions/{execution_id}",
                headers={"Authorization": f"Bearer {other_tenant_token}"},
            )
            assert cross_tenant_status.status_code == 404, cross_tenant_status.text

            # A valid identity cannot read another principal's resource just because it shares a tenant.
            denied = client.post(
                "/v1/authorizations",
                headers=auth_headers,
                json={
                    "action": "file.read",
                    "resource_id": denied_resource_id,
                    "arguments": {},
                },
            )
            assert denied.status_code == 403, denied.text

            # Tenant is derived from the signed provider claim; an unknown tenant-scoped resource stays hidden.
            wrong_tenant = client.post(
                "/v1/authorizations",
                headers=auth_headers,
                json={
                    "action": "file.read",
                    "resource_id": "resource-in-another-tenant",
                    "arguments": {},
                },
            )
            assert wrong_tenant.status_code == 404, wrong_tenant.text
    finally:
        # Audit events are append-only by design, including for the runtime role.
        # Preserve those evidence records; clean only the FK-linked mutable test rows.
        with psycopg.connect(ADMIN_DATABASE_URL, row_factory=dict_row) as admin:
            admin.execute(
                """
                DELETE FROM authz_executions
                WHERE tenant_id = %s
                  AND permit_id IN (
                    SELECT permit_id FROM authz_permits
                    WHERE tenant_id = %s AND resource_id IN (%s, %s)
                  )
                """,
                (principal.tenant_id, principal.tenant_id, resource_id, denied_resource_id),
            )
            admin.execute(
                "DELETE FROM authz_permits WHERE tenant_id = %s AND resource_id IN (%s, %s)",
                (principal.tenant_id, resource_id, denied_resource_id),
            )
            admin.execute(
                "DELETE FROM protected_resources WHERE tenant_id = %s AND resource_id IN (%s, %s)",
                (principal.tenant_id, resource_id, denied_resource_id),
            )
