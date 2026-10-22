from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import os
import unittest
import uuid

from paca_mvp.durable import PostgresOperationStore


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


if __name__ == "__main__":
    unittest.main()
