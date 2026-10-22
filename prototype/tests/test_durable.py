from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import json
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path

from paca_mvp.durable import (
    IdempotencyConflict,
    OperationOutcomeUnknown,
    OperationStateError,
    SQLiteOperationStore,
    canonical_json,
)


class DurableStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp.name) / "state.db")
        self.store = SQLiteOperationStore(self.db_path)
        self.key = "test-key-" + uuid.uuid4().hex[:12]
        self.kwargs = {
            "idempotency_key": self.key,
            "principal_id": "user-1",
            "action": "file.read",
            "resource": "file:r1",
            "arguments_digest": "a" * 64,
            "context_digest": "b" * 64,
            "policy_decision": {"allow": True, "reason": "permitted"},
            "ttl_seconds": 30,
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_lifecycle_and_cached_result(self):
        record, created = self.store.create_or_get(**self.kwargs)
        self.assertTrue(created)
        self.assertEqual(record.status, "issued")
        claimed = self.store.claim(record.operation_id)
        self.assertEqual(claimed.status, "in_progress")
        done = self.store.complete(record.operation_id, {"ok": True, "value": 3})
        self.assertEqual(done.status, "succeeded")
        self.assertEqual(done.response, {"ok": True, "value": 3})
        replay, replay_created = self.store.create_or_get(**self.kwargs)
        self.assertFalse(replay_created)
        self.assertEqual(replay.status, "succeeded")
        self.assertEqual(replay.response, {"ok": True, "value": 3})
        self.assertTrue(self.store.verify_audit_chain())

    def test_idempotency_key_cannot_be_reused_for_different_arguments(self):
        self.store.create_or_get(**self.kwargs)
        altered = dict(self.kwargs)
        altered["arguments_digest"] = "c" * 64
        with self.assertRaises(IdempotencyConflict):
            self.store.create_or_get(**altered)
        self.assertTrue(self.store.verify_audit_chain())

    def test_duplicate_claim_cannot_dispatch_twice(self):
        record, _ = self.store.create_or_get(**self.kwargs)
        self.store.claim(record.operation_id)
        with self.assertRaisesRegex(OperationStateError, "operation_in_progress"):
            self.store.claim(record.operation_id)

    def test_unknown_outcome_is_not_retried_and_can_be_reconciled(self):
        record, _ = self.store.create_or_get(**self.kwargs)
        self.store.claim(record.operation_id)
        self.store.mark_unknown(record.operation_id, "TimeoutError")
        current = self.store.get_operation(record.operation_id)
        self.assertEqual(current.status, "unknown")
        with self.assertRaises(OperationOutcomeUnknown):
            self.store.claim(record.operation_id)
        resolved = self.store.reconcile_unknown(
            record.operation_id, outcome="succeeded", reason="checked_downstream_log",
            response={"remote_id": "r-1"},
        )
        self.assertEqual(resolved.status, "succeeded")
        self.assertEqual(resolved.response, {"remote_id": "r-1"})
        self.assertTrue(self.store.verify_audit_chain())

    def test_recovery_marks_stale_in_progress_as_unknown(self):
        record, _ = self.store.create_or_get(**self.kwargs)
        self.store.claim(record.operation_id)
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                "UPDATE operations SET started_at=? WHERE operation_id=?",
                ("2000-01-01T00:00:00+00:00", record.operation_id),
            )
        self.assertEqual(self.store.recover_incomplete(older_than_seconds=5), 1)
        self.assertEqual(self.store.get_operation(record.operation_id).status, "unknown")

    def test_audit_tampering_is_detected(self):
        self.store.record_denial("user-1", "file.read", "file:r1", "test")
        self.assertTrue(self.store.verify_audit_chain())
        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute("SELECT seq,payload_json FROM audit_events LIMIT 1").fetchone()
            payload = json.loads(row[1])
            payload["reason"] = "tampered"
            connection.execute("UPDATE audit_events SET payload_json=? WHERE seq=?",
                               (json.dumps(payload), row[0]))
        self.assertFalse(self.store.verify_audit_chain())

    def test_second_store_instance_observes_claim_across_connections(self):
        record, _ = self.store.create_or_get(**self.kwargs)
        second_store = SQLiteOperationStore(self.db_path)
        second_store.claim(record.operation_id)
        with self.assertRaisesRegex(OperationStateError, "operation_in_progress"):
            self.store.claim(record.operation_id)


    def test_canonical_json_rejects_non_string_keys_and_non_finite_values(self):
        for value in ({1: "one"}, {"nan": float("nan")}, {"infinity": float("inf")}):
            with self.subTest(value=str(value)):
                with self.assertRaises(ValueError):
                    canonical_json(value)

    def test_canonical_json_enforces_nesting_limit(self):
        value = {}
        cursor = value
        for _ in range(67):
            cursor["child"] = {}
            cursor = cursor["child"]
        with self.assertRaises(ValueError):
            canonical_json(value)


if __name__ == "__main__":
    unittest.main()
