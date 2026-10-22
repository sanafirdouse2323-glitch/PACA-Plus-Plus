from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import contextlib
import io
import json
import tempfile
import sys
from unittest.mock import patch
import unittest
import uuid
from pathlib import Path

from paca_mvp.durable import SQLiteOperationStore
from paca_mvp.ops import main


class OperationsCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "ops.db")
        self.store = SQLiteOperationStore(self.path)
        record, _ = self.store.create_or_get(
            idempotency_key="ops-" + uuid.uuid4().hex,
            principal_id="operator-test-user",
            action="file.read",
            resource="file:r1",
            arguments_digest="a" * 64,
            context_digest="b" * 64,
            policy_decision={"allow": True, "reason": "test"},
            ttl_seconds=30,
        )
        self.operation_id = record.operation_id
        self.store.claim(self.operation_id)
        self.store.mark_unknown(self.operation_id, "timeout")

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, command, *args, stdin_text=None):
        output = io.StringIO()
        supplied_stdin = io.StringIO(stdin_text) if stdin_text is not None else sys.stdin
        with contextlib.redirect_stdout(output), patch("sys.stdin", supplied_stdin):
            status = main(["--backend", "sqlite", "--path", self.path, command, *args])
        return status, json.loads(output.getvalue()) if output.getvalue().strip() else None

    def test_show_operation_omits_response_and_raw_arguments(self):
        status, payload = self.invoke("show-operation", "--operation-id", self.operation_id)
        self.assertEqual(status, 0)
        self.assertEqual(payload["status"], "unknown")
        self.assertNotIn("response", payload)
        self.assertNotIn("arguments", payload)

    def test_unknown_outcome_requires_audited_reconciliation(self):
        status, payload = self.invoke(
            "reconcile-unknown", "--operation-id", self.operation_id,
            "--outcome", "succeeded", "--reason", "verified_downstream_record_123",
            "--response-stdin",
            stdin_text='{"remote_id":"remote-123"}',
        )
        self.assertEqual(status, 0)
        self.assertEqual(payload["status"], "succeeded")
        self.assertTrue(self.store.verify_audit_chain())
        self.assertEqual(self.store.get_operation(self.operation_id).response, {"remote_id": "remote-123"})

    def test_audit_verification_command_returns_success_for_valid_chain(self):
        status, payload = self.invoke("verify-audit")
        self.assertEqual(status, 0)
        self.assertTrue(payload["audit_chain_valid"])

    def test_success_reconciliation_requires_response_json(self):
        status = main([
            "--backend", "sqlite", "--path", self.path, "reconcile-unknown",
            "--operation-id", self.operation_id, "--outcome", "succeeded",
            "--reason", "checked_downstream",
        ])
        self.assertEqual(status, 2)
        self.assertEqual(self.store.get_operation(self.operation_id).status, "unknown")


if __name__ == "__main__":
    unittest.main()
