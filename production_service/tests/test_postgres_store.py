from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from psycopg.types.json import Jsonb

from paca_service.security import canonical_digest
from paca_service.store import PostgresStore

DATABASE_URL = os.getenv("PACA_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="PACA_TEST_DATABASE_URL is required for PostgreSQL concurrency/recovery tests",
)


class TestPostgresStoreIntegration:
    def setup_method(self):
        self.store = PostgresStore(DATABASE_URL)
        self.store.open()
        self.tenant_id = "test-" + uuid4().hex
        self.principal_id = "integration-user"
        self.resource_id = "file-" + uuid4().hex
        self.attributes = {"relative_path": "integration.txt"}
        with self.store.pool.connection() as conn:
            conn.execute(
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
        with pytest.raises(Exception, match="append-only"), self.store.pool.connection() as conn:
                conn.execute(
                    "UPDATE audit_events SET event_type = 'tampered' "
                    "WHERE event_type = 'integration-test' AND tenant_id = %s",
                    (self.tenant_id,),
                )
