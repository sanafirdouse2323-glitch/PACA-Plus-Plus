from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import os
import unittest
import uuid

from paca_mvp.durable import OperationStateError, PostgresOperationStore


DSN = os.environ.get("PACA_TEST_DATABASE_URL")


@unittest.skipUnless(DSN, "Set PACA_TEST_DATABASE_URL to run PostgreSQL integration tests")
class PostgresStoreIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = PostgresOperationStore(DSN)

    def test_durable_claim_completion_and_audit_under_postgres(self):
        key = "pg-" + uuid.uuid4().hex
        record, created = self.store.create_or_get(
            idempotency_key=key,
            principal_id="integration-user",
            action="file.read",
            resource="file:r-integration",
            arguments_digest="a" * 64,
            context_digest="b" * 64,
            policy_decision={"allow": True, "reason": "integration_test"},
            ttl_seconds=30,
        )
        self.assertTrue(created)
        self.store.claim(record.operation_id)
        result = self.store.complete(record.operation_id, {"integration": True})
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(result.response, {"integration": True})
        self.assertTrue(self.store.verify_audit_chain())


    def test_idempotency_keys_are_scoped_by_principal_in_postgres(self):
        key = "pg-shared-" + uuid.uuid4().hex
        common = {
            "idempotency_key": key,
            "action": "file.read",
            "resource": "file:r-same-key",
            "arguments_digest": "a" * 64,
            "context_digest": "b" * 64,
            "policy_decision": {"allow": True, "reason": "integration_test"},
            "ttl_seconds": 30,
        }
        first, first_created = self.store.create_or_get(**common, principal_id="postgres-user-a")
        second, second_created = self.store.create_or_get(**common, principal_id="postgres-user-b")
        self.assertTrue(first_created)
        self.assertTrue(second_created)
        self.assertNotEqual(first.operation_id, second.operation_id)
        self.assertTrue(self.store.verify_audit_chain())


    def test_concurrent_create_and_claim_are_coordinated_across_clients(self):
        import threading

        key = "pg-race-" + uuid.uuid4().hex
        common = {
            "idempotency_key": key,
            "principal_id": "integration-racer",
            "action": "file.read",
            "resource": "file:r-race",
            "arguments_digest": "d" * 64,
            "context_digest": "e" * 64,
            "policy_decision": {"allow": True, "reason": "integration_test"},
            "ttl_seconds": 30,
        }
        barrier = threading.Barrier(2)
        created = []
        errors = []

        def create():
            try:
                barrier.wait(timeout=5)
                created.append(PostgresOperationStore(DSN).create_or_get(**common))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=create) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(sum(1 for _, was_created in created if was_created), 1)
        self.assertEqual(len({record.operation_id for record, _ in created}), 1)

        operation_id = created[0][0].operation_id
        barrier = threading.Barrier(2)
        claims = []
        claim_errors = []

        def claim():
            try:
                barrier.wait(timeout=5)
                claims.append(PostgresOperationStore(DSN).claim(operation_id))
            except Exception as exc:
                claim_errors.append(exc)

        threads = [threading.Thread(target=claim) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(sum(1 for record in claims if record.status == "in_progress"), 1)
        self.assertEqual(len(claim_errors), 1)
        self.assertIsInstance(claim_errors[0], OperationStateError)
        self.assertTrue(self.store.verify_audit_chain())


    def test_postgres_readiness_checks_required_tables(self):
        self.assertIsNone(self.store.check_ready())


    def test_migration_limits_runtime_and_operator_to_mutable_columns(self):
        import psycopg

        with psycopg.connect(DSN, autocommit=True) as connection:
            permissions = connection.execute("""
                SELECT
                    has_table_privilege('paca_runtime', 'paca.operations', 'UPDATE'),
                    has_column_privilege('paca_runtime', 'paca.operations', 'status', 'UPDATE'),
                    has_column_privilege('paca_runtime', 'paca.operations', 'request_fingerprint', 'UPDATE'),
                    has_table_privilege('paca_operator', 'paca.operations', 'UPDATE'),
                    has_column_privilege('paca_operator', 'paca.operations', 'status', 'UPDATE'),
                    has_column_privilege('paca_operator', 'paca.operations', 'request_fingerprint', 'UPDATE')
            """).fetchone()
            self.assertEqual(tuple(permissions), (False, True, False, False, True, False))

            connection.execute("SET ROLE paca_runtime")
            connection.execute("UPDATE paca.operations SET status=status WHERE false")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "UPDATE paca.operations SET request_fingerprint=request_fingerprint WHERE false"
                )

            connection.execute("RESET ROLE")
            connection.execute("SET ROLE paca_operator")
            connection.execute("UPDATE paca.operations SET status=status WHERE false")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "UPDATE paca.operations SET request_fingerprint=request_fingerprint WHERE false"
                )


if __name__ == "__main__":
    unittest.main()
