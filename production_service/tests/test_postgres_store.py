from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import psycopg
import pytest
from psycopg.errors import InsufficientPrivilege
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

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
                    has_table_privilege(current_user, 'protected_resources', 'UPDATE') AS can_update_resources,
                    has_table_privilege(current_user, 'audit_events', 'SELECT') AS can_read_audit,
                    has_table_privilege(current_user, 'audit_events', 'UPDATE') AS can_update_audit,
                    has_table_privilege(current_user, 'audit_events', 'DELETE') AS can_delete_audit
                """
            ).fetchone()
            rls_rows = conn.execute(
                """
                SELECT c.relname, c.relrowsecurity,
                       (c.relowner = r.oid) AS runtime_is_owner
                FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                CROSS JOIN pg_roles AS r
                WHERE n.nspname = 'public' AND r.rolname = current_user
                  AND c.relname IN (
                    'protected_resources', 'authz_permits',
                    'authz_executions', 'audit_events'
                  )
                """
            ).fetchall()
        assert role is not None
        assert role["rolsuper"] is False
        assert role["rolcreatedb"] is False
        assert role["rolcreaterole"] is False
        assert role["rolbypassrls"] is False
        assert privileges["can_read_resources"] is True
        assert privileges["can_insert_resources"] is False
        assert privileges["can_update_resources"] is False
        assert privileges["can_read_audit"] is True
        assert privileges["can_update_audit"] is False
        assert privileges["can_delete_audit"] is False
        rls = {row["relname"]: row for row in rls_rows}
        assert set(rls) == {
            "protected_resources", "authz_permits", "authz_executions", "audit_events"
        }
        for table, details in rls.items():
            assert details["relrowsecurity"] is True, table
            assert details["runtime_is_owner"] is False, table

    def test_rls_prevents_cross_tenant_direct_reads_updates_and_mismatched_execution_links(self):
        other_tenant = "other-" + uuid4().hex
        other_principal = "other-user-" + uuid4().hex
        other_resource = "file-" + uuid4().hex
        other_attributes = {"relative_path": "other.txt"}
        with psycopg.connect(ADMIN_DATABASE_URL, row_factory=dict_row) as admin:
            admin.execute(
                """
                INSERT INTO protected_resources
                    (tenant_id, resource_id, owner_id, kind, status, attributes)
                VALUES (%s, %s, %s, 'file', 'active', %s)
                """,
                (other_tenant, other_resource, other_principal, Jsonb(other_attributes)),
            )

        other_context = {
            "principal": {
                "id": other_principal, "tenant_id": other_tenant,
                "roles": [], "scopes": ["file:read"], "tools": [],
            },
            "action": "file.read",
            "resource": {
                "id": other_resource, "tenant_id": other_tenant,
                "owner_id": other_principal, "kind": "file", "status": "active",
                "attributes": other_attributes,
            },
            "arguments": {},
        }
        other_permit = self.store.issue_permit(
            tenant_id=other_tenant, principal_id=other_principal,
            action="file.read", resource_id=other_resource,
            arguments_digest=self.arguments_digest,
            context_digest=canonical_digest(other_context),
            policy_revision="test-revision", decision_id="other-decision",
            ttl_seconds=60, request_id="other-request",
        )
        other_claim = self.store.claim_execution(
            permit_id=other_permit.permit_id, tenant_id=other_tenant,
            principal_id=other_principal, action="file.read",
            resource_id=other_resource, arguments_digest=self.arguments_digest,
            context_digest=canonical_digest(other_context), policy_revision="test-revision",
            idempotency_key="other-" + uuid4().hex, context=other_context,
            request_id="other-request",
        )
        assert other_claim.disposition == "claimed"
        self.store.record_audit(
            event_type="tenant-b-private-audit", tenant_id=other_tenant,
            principal_id=other_principal, request_id="other-request",
            action="file.read", resource_id=other_resource,
        )

        # Deliberately use direct table queries, not PostgresStore's tenant-aware methods.
        # With tenant A in transaction context, omitted WHERE clauses and explicit
        # tenant-B lookups must both be constrained by PostgreSQL RLS.
        with self.store.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT set_config('paca.tenant_id', %s, true)", (self.tenant_id,))
            assert conn.execute(
                "SELECT count(*) AS n FROM authz_permits"
            ).fetchone()["n"] == 1
            assert conn.execute(
                "SELECT count(*) AS n FROM protected_resources"
            ).fetchone()["n"] == 1
            for table, key, value in (
                ("protected_resources", "resource_id", other_resource),
                ("authz_permits", "permit_id", other_permit.permit_id),
                ("authz_executions", "execution_id", other_claim.execution_id),
                ("audit_events", "tenant_id", other_tenant),
            ):
                row = conn.execute(
                    f"SELECT 1 FROM public.{table} WHERE {key} = %s LIMIT 1", (value,)
                ).fetchone()
                assert row is None, table

            # RLS WITH CHECK must reject tenant reassignment even when the target
            # tenant/resource pair itself exists and would satisfy ordinary FKs.
            with pytest.raises(InsufficientPrivilege), conn.transaction():
                conn.execute(
                        """
                        UPDATE authz_permits
                        SET tenant_id = %s, principal_id = %s, resource_id = %s
                        WHERE permit_id = %s
                        """,
                        (other_tenant, other_principal, other_resource, self.permit.permit_id),
                    )

        # A direct insert under tenant B cannot attach tenant A's permit to B's
        # execution row; this must fail even though B is the active RLS context.
        with self.store.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT set_config('paca.tenant_id', %s, true)", (other_tenant,))
            with pytest.raises(psycopg.errors.ForeignKeyViolation), conn.transaction():
                conn.execute(
                        """
                        INSERT INTO authz_executions
                            (execution_id, permit_id, tenant_id, principal_id,
                             idempotency_key, request_digest, status)
                        VALUES (%s, %s, %s, %s, %s, %s, 'executing')
                        """,
                        (uuid4(), self.permit.permit_id, other_tenant, other_principal,
                         "bad-" + uuid4().hex, "a" * 64),
                    )

        # Missing tenant context is fail-closed for all tenant-scoped tables.
        with self.store.pool.connection() as conn, conn.transaction():
            for table in ("protected_resources", "authz_permits", "authz_executions", "audit_events"):
                assert conn.execute(f"SELECT count(*) AS n FROM public.{table}").fetchone()["n"] == 0

    def test_resource_lock_function_rejects_tenant_mismatch_with_transaction_context(self):
        other_tenant_id = "other-" + uuid4().hex
        other_resource_id = "file-" + uuid4().hex
        with psycopg.connect(ADMIN_DATABASE_URL, row_factory=dict_row) as admin:
            admin.execute(
                """
                INSERT INTO protected_resources
                    (tenant_id, resource_id, owner_id, kind, status, attributes)
                VALUES (%s, %s, %s, 'file', 'active', %s)
                """,
                (other_tenant_id, other_resource_id, self.principal_id, Jsonb(self.attributes)),
            )

        with self.store.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT set_config('paca.tenant_id', %s, true)", (self.tenant_id,))
            row = conn.execute(
                "SELECT * FROM public.paca_lock_resource_for_execution(%s, %s)",
                (other_tenant_id, other_resource_id),
            ).fetchone()
        assert row is None

    def test_concurrent_claim_consumes_permit_at_most_once_and_replays_durably(self):
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: self.claim("same-key"), range(2)))
        dispositions = sorted(item.disposition for item in results)
        assert dispositions == ["claimed", "in_progress"]
        execution_id = next(item.execution_id for item in results if item.disposition == "claimed")
        self.store.finish_execution(
            execution_id=execution_id, tenant_id=self.tenant_id,
            principal_id=self.principal_id, outcome="succeeded", result={"ok": True},
            error_code=None, request_id="test-request",
        )
        replay = self.claim("same-key")
        assert replay.disposition == "replayed_success"
        assert replay.execution_id == execution_id
        assert replay.result == {"ok": True}

    def test_stale_execution_is_classified_unknown_not_automatically_retried(self):
        claim = self.claim("stale-key")
        assert claim.disposition == "claimed"
        with self.store.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT set_config('paca.tenant_id', %s, true)", (self.tenant_id,))
            conn.execute(
                """UPDATE authz_executions
                   SET started_at = now() - interval '10 minutes'
                   WHERE execution_id = %s AND tenant_id = %s AND principal_id = %s""",
                (claim.execution_id, self.tenant_id, self.principal_id),
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
        with self.store.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT set_config('paca.tenant_id', %s, true)", (self.tenant_id,))
            row = conn.execute(
                "SELECT event_id FROM audit_events WHERE event_type = 'integration-test' AND tenant_id = %s LIMIT 1",
                (self.tenant_id,),
            ).fetchone()
        assert row is not None
        with pytest.raises(InsufficientPrivilege), self.store.pool.connection() as conn:
            conn.execute(
                "UPDATE audit_events SET event_type = 'tampered' WHERE event_id = %s",
                (row["event_id"],),
            )
        with pytest.raises(InsufficientPrivilege), self.store.pool.connection() as conn:
            conn.execute("DELETE FROM audit_events WHERE event_id = %s", (row["event_id"],))

    def test_runtime_role_cannot_escalate_or_mutate_privileged_objects(self):
        """Exercise database grants, separately from row-level tenant policies."""
        with self.store.pool.connection() as conn:
            grants = conn.execute(
                """
                SELECT
                    has_schema_privilege(current_user, 'public', 'CREATE') AS can_create_in_public,
                    has_table_privilege(current_user, 'protected_resources', 'DELETE') AS can_delete_resources,
                    has_table_privilege(current_user, 'authz_permits', 'DELETE') AS can_delete_permits,
                    has_table_privilege(current_user, 'authz_executions', 'DELETE') AS can_delete_executions,
                    has_table_privilege(current_user, 'audit_events', 'UPDATE') AS can_update_audit,
                    has_table_privilege(current_user, 'audit_events', 'DELETE') AS can_delete_audit,
                    has_function_privilege(
                        current_user, 'public.paca_reject_audit_mutation()', 'EXECUTE'
                    ) AS can_call_audit_trigger_function
                """
            ).fetchone()
        assert grants["can_create_in_public"] is False
        assert grants["can_delete_resources"] is False
        assert grants["can_delete_permits"] is False
        assert grants["can_delete_executions"] is False
        assert grants["can_update_audit"] is False
        assert grants["can_delete_audit"] is False
        assert grants["can_call_audit_trigger_function"] is False

        table_name = "runtime_escalation_probe_" + uuid4().hex
        with pytest.raises(InsufficientPrivilege), self.store.pool.connection() as conn:
            conn.execute(f"CREATE TABLE public.{table_name} (id integer)")

        # A runtime login must not be able to assume the administrative role.
        with pytest.raises(
            (InsufficientPrivilege, psycopg.errors.InvalidAuthorizationSpecification)
        ), self.store.pool.connection() as conn:
            conn.execute("SET ROLE paca")

    def test_security_definer_functions_are_pinned_and_recovery_threshold_is_bounded(self):
        with self.store.pool.connection() as conn:
            functions = conn.execute(
                """
                SELECT p.proname, p.prosecdef, p.proconfig,
                       pg_get_userbyid(p.proowner) AS function_owner,
                       has_function_privilege(current_user, p.oid, 'EXECUTE') AS runtime_can_execute
                FROM pg_proc AS p
                JOIN pg_namespace AS n ON n.oid = p.pronamespace
                WHERE n.nspname = 'public'
                  AND p.proname IN (
                    'paca_lock_resource_for_execution',
                    'paca_mark_stale_executions_unknown'
                  )
                """
            ).fetchall()
        by_name = {row["proname"]: row for row in functions}
        assert set(by_name) == {
            "paca_lock_resource_for_execution",
            "paca_mark_stale_executions_unknown",
        }
        for row in by_name.values():
            assert row["prosecdef"] is True
            assert row["function_owner"] != "paca_runtime"
            assert any(
                setting.replace(" ", "") == "search_path=pg_catalog,public"
                for setting in (row["proconfig"] or [])
            )
            assert row["runtime_can_execute"] is True

        # The cross-tenant recovery function is intentionally callable by the
        # runtime role; reject out-of-range thresholds at the database boundary.
        for threshold in (0, 86401):
            with pytest.raises(psycopg.errors.InvalidParameterValue), self.store.pool.connection() as conn:
                conn.execute(
                    "SELECT public.paca_mark_stale_executions_unknown(%s)",
                    (threshold,),
                )

    def test_compromised_runtime_credential_can_change_rls_tenant_context(self):
        """Executable evidence of the documented stolen-DB-credential boundary.

        This is not a passing tenant-isolation control: it proves that custom GUC
        RLS context is trusted application state, not a database-authenticated
        tenant identity. A party holding the raw runtime credential can switch
        the setting and read/update another tenant's permit. Keep this test so
        the residual risk remains explicit rather than claiming RLS prevents it.
        """
        other_tenant = "compromised-" + uuid4().hex
        other_principal = "other-user-" + uuid4().hex
        other_resource = "file-" + uuid4().hex
        other_permit = uuid4()
        with psycopg.connect(ADMIN_DATABASE_URL, row_factory=dict_row) as admin:
            admin.execute(
                """
                INSERT INTO protected_resources
                    (tenant_id, resource_id, owner_id, kind, status, attributes)
                VALUES (%s, %s, %s, 'file', 'active', %s)
                """,
                (other_tenant, other_resource, other_principal, Jsonb({"relative_path": "private.txt"})),
            )
            admin.execute(
                """
                INSERT INTO authz_permits
                    (permit_id, tenant_id, principal_id, action, resource_id,
                     arguments_digest, context_digest, policy_revision, decision_id,
                     status, expires_at)
                VALUES (%s, %s, %s, 'file.read', %s, %s, %s, 'test-revision',
                        'security-test', 'issued', now() + interval '10 minutes')
                """,
                (other_permit, other_tenant, other_principal, other_resource,
                 self.arguments_digest, "b" * 64),
            )

        with self.store.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT set_config('paca.tenant_id', %s, true)", (self.tenant_id,))
            assert conn.execute(
                "SELECT 1 FROM protected_resources WHERE tenant_id = %s AND resource_id = %s",
                (other_tenant, other_resource),
            ).fetchone() is None
            conn.execute("SELECT set_config('paca.tenant_id', %s, true)", (other_tenant,))
            leaked_resource = conn.execute(
                "SELECT tenant_id, resource_id FROM protected_resources WHERE resource_id = %s",
                (other_resource,),
            ).fetchone()
            assert leaked_resource == {
                "tenant_id": other_tenant, "resource_id": other_resource
            }
            changed = conn.execute(
                """
                UPDATE authz_permits SET status = 'revoked'
                WHERE tenant_id = %s AND permit_id = %s
                RETURNING status
                """,
                (other_tenant, other_permit),
            ).fetchone()
            assert changed == {"status": "revoked"}

        with psycopg.connect(ADMIN_DATABASE_URL, row_factory=dict_row) as admin:
            status = admin.execute(
                "SELECT status FROM authz_permits WHERE permit_id = %s", (other_permit,)
            ).fetchone()
        assert status == {"status": "revoked"}

