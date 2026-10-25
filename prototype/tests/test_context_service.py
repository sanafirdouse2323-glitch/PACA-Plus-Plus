from __future__ import annotations

import os
import sys
import unittest
import uuid
from pathlib import Path
from unittest.mock import Mock

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from paca_mvp.context_service import (
    ContextRepositoryUnavailable,
    PostgresAuthorizationContextRepository,
    create_context_app,
)

TOKEN = "context-service-test-token-" + "x" * 20


class FakeRepository:
    def __init__(self):
        self.calls = []
        self.fail = False

    def ping(self):
        if self.fail:
            raise ContextRepositoryUnavailable("private database failure")

    def get_context(self, subject, issuer, audience, action, resource):
        if self.fail:
            raise ContextRepositoryUnavailable("private database failure")
        self.calls.append((subject, issuer, audience, action, resource))
        return {
            "authorization": {
                "principal_id": "internal-user-17",
                "tenant_id": "tenant-a",
                "role": "analyst",
                "can_create_tickets": False,
                "suspended": False,
            },
            "resource": {
                "tenant_id": "tenant-a",
                "owner_principal_id": "internal-user-17",
            },
        }


class ContextServiceHTTPTests(unittest.TestCase):
    def setUp(self):
        self.repo = FakeRepository()
        self.client = TestClient(create_context_app(repository=self.repo, service_token=TOKEN))
        self.payload = {
            "subject": "raw-oidc-subject",
            "issuer": "https://issuer.example",
            "audience": "paca-api",
            "action": "file.read",
            "resource": "file:report-17",
        }

    def call_context(self, headers=None, payload=None):
        return self.client.post(
            "/v1/attributes",
            json=self.payload if payload is None else payload,
            headers=({"Authorization": "Bearer " + TOKEN} if headers is None else headers),
        )

    def test_endpoint_authenticates_service_and_returns_database_authority(self):
        response = self.call_context()
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["authorization"]["principal_id"], "internal-user-17")
        self.assertEqual(body["resource"]["owner_principal_id"], "internal-user-17")
        self.assertNotIn("identity", body)
        self.assertEqual(self.repo.calls, [
            ("raw-oidc-subject", "https://issuer.example", "paca-api",
             "file.read", "file:report-17")
        ])

    def test_missing_invalid_or_wrong_scheme_credentials_are_rejected(self):
        for headers in (
            {},
            {"Authorization": "Basic " + TOKEN},
            {"Authorization": "Bearer incorrect-secret"},
        ):
            with self.subTest(headers=list(headers)):
                response = self.call_context(headers=headers)
                self.assertEqual(response.status_code, 401)
        self.assertEqual(self.repo.calls, [])

    def test_oversized_context_request_is_rejected_before_json_parsing(self):
        response = self.client.post(
            "/v1/attributes",
            content=b"x" * (16 * 1024 + 1),
            headers={
                "Authorization": "Bearer " + TOKEN,
                "Content-Type": "application/json",
            },
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.repo.calls, [])

    def test_duplicate_authorization_headers_are_rejected_before_lookup(self):
        response = self.call_context(headers=[
            ("Authorization", "Bearer " + TOKEN),
            ("Authorization", "Bearer attacker-token"),
        ])
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.repo.calls, [])

    def test_caller_cannot_supply_roles_capabilities_or_owner_attributes(self):
        response = self.call_context(payload={
            **self.payload,
            "authorization": {"role": "support", "can_create_tickets": True},
            "resource_context": {"owner_principal_id": "attacker"},
        })
        self.assertEqual(response.status_code, 422)
        self.assertEqual(self.repo.calls, [])

    def test_readiness_reports_repository_outage_without_leaking_details(self):
        self.repo.fail = True
        response = self.client.get("/readyz")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("private database failure", response.text)

    def test_remote_context_database_requires_full_tls_verification(self):
        with self.assertRaisesRegex(ValueError, "sslmode=verify-full"):
            PostgresAuthorizationContextRepository(
                "postgresql://user:password@db.example/paca"
            )


DSN = os.environ.get("PACA_TEST_POSTGRES_DSN")


@unittest.skipUnless(DSN, "set PACA_TEST_POSTGRES_DSN to run PostgreSQL context integration tests")
class PostgresAuthorizationContextTests(unittest.TestCase):
    def test_context_uses_internal_identity_current_status_and_resource_tenant(self):
        repository = PostgresAuthorizationContextRepository(DSN)
        suffix = uuid.uuid4().hex
        subject = "sub-" + suffix
        issuer = "https://issuer-" + suffix + ".example"
        audience = "paca-test-" + suffix
        tenant = "tenant-" + suffix
        principal_id = "principal-" + suffix
        resource = "file:resource-" + suffix

        try:
            with repository._psycopg.connect(
                repository.dsn,
                connect_timeout=repository.connect_timeout,
                row_factory=repository._dict_row,
            ) as db:
                db.execute(
                    """INSERT INTO paca_context_principals
                       (principal_id, issuer, subject, audience, tenant_id, role,
                        can_create_tickets, suspended, active)
                       VALUES (%s,%s,%s,%s,%s,'analyst',FALSE,FALSE,TRUE)""",
                    (principal_id, issuer, subject, audience, tenant),
                )
                db.execute(
                    """INSERT INTO paca_context_resources
                       (resource, tenant_id, owner_principal_id)
                       VALUES (%s,%s,%s)""",
                    (resource, tenant, principal_id),
                )

            context = repository.get_context(
                subject, issuer, audience, "file.read", resource
            )
            self.assertEqual(context["authorization"]["principal_id"], principal_id)
            self.assertEqual(context["authorization"]["tenant_id"], tenant)
            self.assertEqual(context["resource"]["owner_principal_id"], principal_id)
            self.assertFalse(context["authorization"]["suspended"])

            # Current database suspension overrides the token's previously valid state.
            with repository._psycopg.connect(
                repository.dsn,
                connect_timeout=repository.connect_timeout,
                row_factory=repository._dict_row,
            ) as db:
                db.execute(
                    """UPDATE paca_context_principals SET suspended=TRUE
                       WHERE principal_id=%s AND tenant_id=%s""",
                    (principal_id, tenant),
                )
            changed = repository.get_context(
                subject, issuer, audience, "file.read", resource
            )
            self.assertTrue(changed["authorization"]["suspended"])

            unknown = repository.get_context(
                "other-" + subject, issuer, audience, "file.read", resource
            )
            self.assertIsNone(unknown["authorization"]["principal_id"])
            self.assertTrue(unknown["authorization"]["suspended"])
        finally:
            with repository._psycopg.connect(
                repository.dsn,
                connect_timeout=repository.connect_timeout,
                row_factory=repository._dict_row,
            ) as db:
                db.execute(
                    "DELETE FROM paca_context_resources WHERE resource=%s", (resource,)
                )
                db.execute(
                    """DELETE FROM paca_context_principals
                       WHERE principal_id=%s AND tenant_id=%s""",
                    (principal_id, tenant),
                )


if __name__ == "__main__":
    unittest.main()
