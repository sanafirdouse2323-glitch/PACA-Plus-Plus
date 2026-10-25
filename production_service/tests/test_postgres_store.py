from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import psycopg
from psycopg.errors import InsufficientPrivilege
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
import pytest

from paca_service.security import canonical_digest
from paca_service.store import PostgresStore

DATABASE_URL = os.getenv("PACA_TEST_DATABASE_URL")
ADMIN_DATABASE_URL = os.getenv("PACA_TEST_ADMIN_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL or not ADMIN_DATABASE_URL,
    reason="PACA_TEST_DATABASE_URL and PACA_TEST_ADMIN_DATABASE_URL are required",
)


class TestPostgresStoreIntegration:
    def setup_method(self):
        self.store = PostgresStore(DATABASE_URL)
        self.store.open()
        self.tenant_id = "test-" + uuid4().hex
        self.principal_id = "integration-user"
        self.resource_id = "file-" + uuid4().hex
        self.attributes = {"relative_path": "integration.txt"}

        # Trusted resource metadata is provisioned by an administrator, not
        # by the restricted API role under test.
        with psycopg.connect(ADMIN_DATABASE_URL, row_factory=dict_row) as admin:
            admin.execute(
                """
                INSERT INTO protected_resources
                    (tenant_id, resource_id, owner_id, kind, status, attributes)
                VALUES (%s, %s, %s, 'file', 'active', %s)
                """,
                (self.tenant_id, self.resource_id, self.principal_id, Jsonb(self.attributes)),
            )

        self.context = {
            "principal": {
                "id": self.principal_id, "tenant_id": self.tenant_id,
                "roles": [], "scopes": ["file:read"], "tools": [],
            },
            "action": "file.read",
            "resource": {
                "id": self.resource_id, "tenant_id": self.tenant_id,
                "owner_id": self.principal_id, "kind": "file", "status": "active",
                "attributes": self.attributes,
            },
            "arguments": {},
        }
        self.arguments_digest = canonical_digest({})
        self.context_digest = canonical_digest(self.context)
        self.permit = self.store.issue_permit(
            tenant_id=self.tenant_id, principal_id=self.principal_id,
            action="file.read", resource_id=self.resource_id,
            arguments_digest=self.arguments_digest, context_digest=self.context_digest,
            policy_revision="test-revision", decision_id="test-decision",
            ttl_seconds=60, request_id="test-request",
        )

    def teardown_method(self):
        self.store.close()

    def claim(self, key: str):
        return self.store.claim_execution(
            permit_id=self.permit.permit_id,
            tenant_id=self.tenant_id,
            principal_id=self.principal_id,
            action="file.read",
            resource_id=self.resource_id,
            arguments_digest=self.arguments_digest,
            context_digest=self.context_digest,
            policy_revision="test-revision",
            idempotency_key=key,
            context=self.context,
            request_id="test-request",
        )

    def test_database_connection_uses_least_privilege_runtime_role(self):
        with self.store.pool.connection() as conn:
            role = conn.execute(
                """
                SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls
                FROM pg_roles WHERE rolname = current_user
                """
            ).fetchone()
            privileges = conn.execute(
                """
                SELECT
                    has_table_privilege(current_user, 'protected_resources', 'SELECT') AS can_read_resources,
                    has_table_privilege(current_user, 'protected_resources', 'INSERT') AS can_insert_resources,
                    has_table_privilege(current_user, 'audit_events', 'SELECT') AS can_read_audit,
                    has_table_privilege(current_user, 'audit_events', 'UPDATE') AS can_update_audit,
                    has_table_privilege(current_user, 'audit_events', 'DELETE') AS can_delete_audit
                """
            ).fetchone()
        assert role is not None
        assert role["rolsuper"] is False
        assert role["rolcreatedb"] is False
        assert role["rolcreaterole"] is False
        assert role["rolbypassrls"] is False
        assert privileges["can_read_resources"] is True
        assert privileges["can_insert_resources"] is False
        assert privileges["can_read_audit"] is True
        assert privileges["can_update_audit"] is False
        assert privileges["can_delete_audit"] is False

    def test_concurrent_claim_consumes_permit_at_most_once_and_replays_durably(self):
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: self.claim("same-key"), range(2)))
        dispositions = sorted(item.disposition for item in results)
        assert dispositions == ["claimed", "in_progress"]
        execution_id = next(item.execution_id for item in results if item.disposition == "claimed")
        self.store.finish_execution(
            execution_id=execution_id, outcome="succeeded", result={"ok": True},
            error_code=None, request_id="test-request",
        )
        replay = self.claim("same-key")
        assert replay.disposition == "replayed_success"
        assert replay.execution_id == execution_id
        assert replay.result == {"ok": True}

    def test_stale_execution_is_classified_unknown_not_automatically_retried(self):
        claim = self.claim("stale-key")
        assert claim.disposition == "claimed"
        with self.store.pool.connection() as conn:
            conn.execute(
                "UPDATE authz_executions SET started_at = now() - interval '10 minutes' WHERE execution_id = %s",
                (claim.execution_id,),
            )
        assert self.store.mark_stale_executions_unknown(120) == 1
        status = self.store.get_execution_status(
            claim.execution_id, self.tenant_id, self.principal_id
        )
        assert status is not None and status["status"] == "unknown"
        retry = self.claim("stale-key")
        assert retry.disposition == "outcome_unknown"

    def test_audit_rows_reject_update_and_delete(self):
        self.store.record_audit(
            event_type="integration-test", tenant_id=self.tenant_id,
            principal_id=self.principal_id, request_id="test-request",
        )
        with self.store.pool.connection() as conn:
            row = conn.execute(
                "SELECT event_id FROM audit_events WHERE event_type = 'integration-test' AND tenant_id = %s LIMIT 1",
                (self.tenant_id,),
            ).fetchone()
        assert row is not None
        with pytest.raises(InsufficientPrivilege):
            with self.store.pool.connection() as conn:
                conn.execute(
                    "UPDATE audit_events SET event_type = 'tampered' WHERE event_id = %s",
                    (row["event_id"],),
                )
        with pytest.raises(InsufficientPrivilege):
            with self.store.pool.connection() as conn:
                conn.execute("DELETE FROM audit_events WHERE event_id = %s", (row["event_id"],))
