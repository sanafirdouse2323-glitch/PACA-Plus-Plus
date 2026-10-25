from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.error import URLError
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from paca_mvp.audit_export import (
    AuditDeliveryError, AuditOutboxWorker, HTTPSAuditSink,
)
from paca_mvp.hardening import HardeningError, SQLitePermitStore


TOKEN = "audit-sink-unit-test-token-" + "x" * 20


class FakeResponse:
    status = 201

    def __init__(self, body=b'{"stored":true}'):
        self.body = body

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeSink:
    def __init__(self, fail=False):
        self.fail = fail
        self.events = []

    def append(self, event):
        if self.fail:
            raise RuntimeError("sentinel secret should never be persisted")
        self.events.append(dict(event))


class AuditSinkTests(unittest.TestCase):
    def test_sink_requires_fixed_https_and_long_non_whitespace_secret(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            HTTPSAuditSink("http://audit.example/events", TOKEN)
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            HTTPSAuditSink("https://user:password@audit.example/events", TOKEN)
        with self.assertRaisesRegex(ValueError, "token"):
            HTTPSAuditSink("https://audit.example/events", "short")

    def test_sink_sends_verified_event_with_idempotency_key(self):
        with tempfile.TemporaryDirectory() as temp:
            store = SQLitePermitStore(str(Path(temp) / "paca.sqlite3"))
            store.record_event("test_event", None, "file.read", "file:1", {"safe": True})
            row = store.claim_audit_outbox("worker-test")[0]
            event = json.loads(row["payload_json"])
            sink = HTTPSAuditSink("https://audit.example/v1/events", TOKEN)
            with patch("paca_mvp.audit_export._urlopen_no_redirect",
                       return_value=FakeResponse()) as mocked:
                sink.append(event)
            request = mocked.call_args.args[0]
            self.assertEqual(request.full_url, "https://audit.example/v1/events")
            self.assertEqual(request.get_header("Idempotency-key"), event["event_id"])
            self.assertEqual(request.get_header("X-paca-audit-hash"), event["event_hash"])
            self.assertEqual(request.get_header("Authorization"), "Bearer " + TOKEN)
            self.assertEqual(json.loads(request.data.decode())["event_id"], event["event_id"])

    def test_sink_rejects_payload_tampering_before_network_call(self):
        with tempfile.TemporaryDirectory() as temp:
            store = SQLitePermitStore(str(Path(temp) / "paca.sqlite3"))
            store.record_event("test_event", None, None, None, {"safe": True})
            row = store.claim_audit_outbox("worker-test")[0]
            event = json.loads(row["payload_json"])
            event["details"]["safe"] = False
            sink = HTTPSAuditSink("https://audit.example/v1/events", TOKEN)
            with patch("paca_mvp.audit_export._urlopen_no_redirect") as mocked:
                with self.assertRaisesRegex(AuditDeliveryError, "hash"):
                    sink.append(event)
            mocked.assert_not_called()

    def test_sink_network_error_is_sanitized_for_retry(self):
        sink = HTTPSAuditSink("https://audit.example/v1/events", TOKEN)
        event = {
            "event_id": "a" * 32,
            "event_hash": "b" * 64,
            "created_at": "2026-01-01T00:00:00+00:00",
            "event": "test",
            "permit_id": None,
            "action": None,
            "resource": None,
            "details": {},
            "previous_hash": "0" * 64,
        }
        from paca_mvp.hardening import _digest
        unsigned = dict(event)
        unsigned.pop("event_hash")
        event["event_hash"] = _digest(unsigned)
        with patch("paca_mvp.audit_export._urlopen_no_redirect",
                   side_effect=URLError("secret=do-not-copy")):
            with self.assertRaisesRegex(AuditDeliveryError, "retried") as caught:
                sink.append(event)
        self.assertNotIn("do-not-copy", str(caught.exception))


class AuditOutboxWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLitePermitStore(str(Path(self.temp.name) / "paca.sqlite3"))

    def tearDown(self):
        self.temp.cleanup()

    def test_successful_delivery_marks_event_complete(self):
        self.store.record_event("test_event", None, "file.read", "file:1", {"result": "ok"})
        sink = FakeSink()
        worker = AuditOutboxWorker(self.store, sink, worker_id="worker-success")
        result = worker.run_once()
        self.assertEqual(result, {
            "claimed": 1, "delivered": 1, "retry_scheduled": 0,
            "retry_state_errors": 0, "ack_state_errors": 0,
        })
        self.assertEqual(len(sink.events), 1)
        self.assertEqual(self.store.audit_outbox_counts(), {
            "total": 1, "pending": 0, "delivered": 1,
        })

    def test_failed_delivery_is_retriable_and_raw_error_is_not_persisted(self):
        self.store.record_event("test_event", None, None, None, {"safe": True})
        worker = AuditOutboxWorker(
            self.store, FakeSink(fail=True), worker_id="worker-retry",
            base_retry_seconds=2, max_retry_seconds=10,
        )
        result = worker.run_once()
        self.assertEqual(result["retry_scheduled"], 1)
        self.assertEqual(self.store.audit_outbox_counts()["pending"], 1)
        with self.store._connect() as db:
            row = db.execute("SELECT * FROM audit_outbox").fetchone()
            self.assertEqual(row["last_error_type"], "RuntimeError")
            self.assertNotIn("sentinel secret", row["last_error_type"])
            self.assertGreater(row["next_attempt_at"], row["created_at"])
        # Backoff keeps an outage from causing a tight retry loop.
        self.assertEqual(worker.run_once()["claimed"], 0)

    def test_worker_refuses_to_export_when_source_audit_chain_is_tampered(self):
        self.store.record_event("test_event", None, None, None, {"original": True})
        with self.store._connect() as db:
            db.execute(
                "UPDATE audit SET details_json=?",
                (json.dumps({"original": False}),),
            )
        sink = FakeSink()
        worker = AuditOutboxWorker(self.store, sink, worker_id="worker-broken-chain")
        with self.assertRaisesRegex(HardeningError, "chain failed verification"):
            worker.run_once()
        self.assertEqual(sink.events, [])
        self.assertEqual(self.store.audit_outbox_counts()["delivered"], 0)

    def test_worker_rejects_tampered_outbox_before_calling_sink(self):
        self.store.record_event("test_event", None, None, None, {"original": True})
        with self.store._connect() as db:
            row = db.execute("SELECT event_id,payload_json FROM audit_outbox").fetchone()
            payload = json.loads(row["payload_json"])
            payload["details"]["original"] = False
            db.execute(
                "UPDATE audit_outbox SET payload_json=? WHERE event_id=?",
                (json.dumps(payload), row["event_id"]),
            )
        sink = FakeSink()
        worker = AuditOutboxWorker(self.store, sink, worker_id="worker-tampered")
        result = worker.run_once()
        self.assertEqual(result["retry_scheduled"], 1)
        self.assertEqual(sink.events, [])
        with self.store._connect() as db:
            row = db.execute("SELECT last_error_type FROM audit_outbox").fetchone()
        self.assertEqual(row["last_error_type"], "AuditDeliveryError")

    def test_reopening_legacy_sqlite_store_backfills_existing_audit_events(self):
        path = str(Path(self.temp.name) / "legacy.sqlite3")
        legacy = SQLitePermitStore(path)
        legacy.record_event("historical_event", None, None, None, {"historical": True})
        with legacy._connect() as db:
            db.execute("DROP TABLE audit_outbox")
        reopened = SQLitePermitStore(path)
        self.assertTrue(reopened.verify_audit_chain())
        self.assertEqual(reopened.audit_outbox_counts(), {
            "total": 1, "pending": 1, "delivered": 0,
        })

    def test_outbox_lease_prevents_two_workers_claiming_same_event(self):
        self.store.record_event("test_event", None, None, None, {})
        first = self.store.claim_audit_outbox("worker-one", lease_seconds=30)
        second = self.store.claim_audit_outbox("worker-two", lease_seconds=30)
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        with self.assertRaises(HardeningError):
            self.store.mark_audit_delivered(first[0]["event_id"], "worker-two")
        self.store.mark_audit_delivered(first[0]["event_id"], "worker-one")
        self.assertEqual(self.store.audit_outbox_counts()["pending"], 0)

    def test_expired_lease_can_be_reclaimed_after_worker_crash(self):
        self.store.record_event("test_event", None, None, None, {})
        first = self.store.claim_audit_outbox("worker-crashed", lease_seconds=30)[0]
        with self.store._connect() as db:
            db.execute(
                "UPDATE audit_outbox SET lease_expires_at=? WHERE event_id=?",
                ("2000-01-01T00:00:00+00:00", first["event_id"]),
            )
        second = self.store.claim_audit_outbox("worker-replacement", lease_seconds=30)
        self.assertEqual([r["event_id"] for r in second], [first["event_id"]])
        self.assertEqual(second[0]["attempts"], 2)

    def test_audit_event_and_outbox_intent_rollback_together(self):
        original = self.store._audit
        def add_then_fail(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("simulate transaction failure")
        from unittest.mock import patch
        with patch.object(self.store, "_audit", side_effect=add_then_fail):
            with self.assertRaisesRegex(RuntimeError, "transaction failure"):
                self.store.record_event("must_rollback", None, None, None, {})
        self.assertEqual(self.store.audit_events(), [])
        self.assertEqual(self.store.audit_outbox_counts(), {
            "total": 0, "pending": 0, "delivered": 0,
        })
        self.assertTrue(self.store.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
