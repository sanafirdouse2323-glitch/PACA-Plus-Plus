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
    FernetResponseProtector,
    IdempotencyConflict,
    OperationOutcomeUnknown,
    OperationStateError,
    SQLiteOperationStore,
    StoreError,
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


    def test_same_idempotency_key_is_scoped_to_principal(self):
        first, first_created = self.store.create_or_get(**self.kwargs)
        second_kwargs = dict(self.kwargs)
        second_kwargs["principal_id"] = "different-user"
        second, second_created = self.store.create_or_get(**second_kwargs)
        self.assertTrue(first_created)
        self.assertTrue(second_created)
        self.assertNotEqual(first.operation_id, second.operation_id)
        self.assertEqual(first.idempotency_key, second.idempotency_key)

    def test_existing_sqlite_global_idempotency_constraint_is_migrated(self):
        legacy_path = str(Path(self.temp.name) / "legacy.db")
        with sqlite3.connect(legacy_path) as connection:
            connection.execute("""
                CREATE TABLE operations (
                    operation_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    request_fingerprint TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    arguments_digest TEXT NOT NULL,
                    context_digest TEXT NOT NULL,
                    policy_decision_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    response_json TEXT,
                    error_code TEXT
                )
            """)
            connection.execute("CREATE INDEX operations_status_started ON operations(status, started_at)")
        migrated = SQLiteOperationStore(legacy_path)
        first_kwargs = dict(self.kwargs, idempotency_key="shared-after-migration")
        second_kwargs = dict(first_kwargs, principal_id="different-user")
        first, _ = migrated.create_or_get(**first_kwargs)
        second, _ = migrated.create_or_get(**second_kwargs)
        self.assertNotEqual(first.operation_id, second.operation_id)
        with sqlite3.connect(legacy_path) as connection:
            unique_indexes = connection.execute("PRAGMA index_list('operations')").fetchall()
            unique_columns = []
            for idx in unique_indexes:
                if idx[2]:
                    columns = connection.execute(f'PRAGMA index_info("{idx[1]}")').fetchall()
                    unique_columns.append([col[2] for col in columns])
        self.assertIn(["principal_id", "idempotency_key"], unique_columns)
        self.assertNotIn(["idempotency_key"], unique_columns)


    def test_storage_rejects_malformed_action_resource_principal_and_digests(self):
        bad_cases = [
            {"action": "../admin"},
            {"resource": "bad\nresource"},
            {"principal_id": "bad\nprincipal"},
            {"arguments_digest": "not-a-digest"},
            {"context_digest": "f" * 63},
        ]
        for overrides in bad_cases:
            with self.subTest(overrides=overrides):
                kwargs = dict(self.kwargs)
                kwargs["idempotency_key"] = "validate-" + uuid.uuid4().hex
                kwargs.update(overrides)
                with self.assertRaises(ValueError):
                    self.store.create_or_get(**kwargs)


    def test_cached_response_is_encrypted_at_rest_and_decrypted_for_replay(self):
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            self.skipTest("Install the production extra for response encryption tests")
        key = Fernet.generate_key().decode("ascii")
        protected_store = SQLiteOperationStore(
            str(Path(self.temp.name) / "protected.db"),
            response_protector=FernetResponseProtector([key]),
        )
        record, _ = protected_store.create_or_get(**self.kwargs)
        protected_store.claim(record.operation_id)
        sensitive_response = {"file_content": "this content must not be stored as plaintext"}
        completed = protected_store.complete(record.operation_id, sensitive_response)
        self.assertEqual(completed.response, sensitive_response)
        with sqlite3.connect(str(Path(self.temp.name) / "protected.db")) as connection:
            stored = connection.execute(
                "SELECT response_json FROM operations WHERE operation_id=?", (record.operation_id,)
            ).fetchone()[0]
        self.assertTrue(stored.startswith("enc:v1:"))
        self.assertNotIn("this content must not be stored as plaintext", stored)
        reopened = SQLiteOperationStore(
            str(Path(self.temp.name) / "protected.db"),
            response_protector=FernetResponseProtector([key]),
        )
        self.assertEqual(reopened.get_operation(record.operation_id).response, sensitive_response)

    def test_encrypted_response_cannot_be_read_without_key_or_with_wrong_key(self):
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            self.skipTest("Install the production extra for response encryption tests")
        right = Fernet.generate_key().decode("ascii")
        wrong = Fernet.generate_key().decode("ascii")
        db = str(Path(self.temp.name) / "protected-no-key.db")
        protected_store = SQLiteOperationStore(db, response_protector=FernetResponseProtector([right]))
        record, _ = protected_store.create_or_get(**self.kwargs)
        protected_store.claim(record.operation_id)
        protected_store.complete(record.operation_id, {"secret": "private"})
        with self.assertRaisesRegex(StoreError, "encrypted_cached_response_requires_response_protector"):
            SQLiteOperationStore(db).get_operation(record.operation_id)
        with self.assertRaisesRegex(StoreError, "cached_response_decryption_failed"):
            SQLiteOperationStore(db, response_protector=FernetResponseProtector([wrong])).get_operation(record.operation_id)

    def test_response_encryption_key_rotation_accepts_retiring_decrypt_key(self):
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            self.skipTest("Install the production extra for response encryption tests")
        old_key = Fernet.generate_key().decode("ascii")
        new_key = Fernet.generate_key().decode("ascii")
        db = str(Path(self.temp.name) / "rotation.db")
        old_store = SQLiteOperationStore(db, response_protector=FernetResponseProtector([old_key]))
        record, _ = old_store.create_or_get(**self.kwargs)
        old_store.claim(record.operation_id)
        old_store.complete(record.operation_id, {"remote_result": "stored"})
        rotated = SQLiteOperationStore(
            db, response_protector=FernetResponseProtector([new_key, old_key])
        )
        self.assertEqual(rotated.get_operation(record.operation_id).response, {"remote_result": "stored"})


if __name__ == "__main__":
    unittest.main()
