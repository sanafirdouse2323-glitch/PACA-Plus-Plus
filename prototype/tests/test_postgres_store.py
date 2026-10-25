from __future__ import annotations

import os
import threading
import time
import unittest
import uuid

DSN = os.environ.get("PACA_TEST_POSTGRES_DSN")
_DEFAULT_IDEMPOTENCY = object()
if DSN:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from paca_mvp.postgres import PostgresPermitStore
    from paca_mvp.hardening import (
        EffectOutcomeUnknown, HardeningError, PermitRejected, IdempotencyConflict,
    )


@unittest.skipUnless(DSN, "set PACA_TEST_POSTGRES_DSN to run PostgreSQL integration tests")
class PostgresPermitStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = PostgresPermitStore(DSN, initialize_schema=False)
        token = uuid.uuid4().hex
        self.action = "resource.write"
        self.resource = "test-resource:" + token
        self.request_hash = token * 2
        self.idempotency_key = "test-idempotency:" + token
        self.policy_version = "integration-test-v1"
        self.actor = {
            "subject": "integration-user", "issuer": "https://issuer.example",
            "audience": "paca-test",
        }

    def issue(self, key=_DEFAULT_IDEMPOTENCY):
        idempotency_key = self.idempotency_key if key is _DEFAULT_IDEMPOTENCY else key
        return self.store.issue(
            self.action, self.resource, self.request_hash, self.policy_version,
            idempotency_key=idempotency_key, actor=self.actor,
        )

    def test_schema_initialization_reseeds_missing_audit_head_from_existing_history(self):
        self.store.record_event("pre_migration_event", None, None, None, {"marker": "existing"})
        self.assertTrue(self.store.verify_audit_chain())
        with self.store._connect() as db:
            original_head = db.execute(
                "SELECT event_hash FROM paca_audit_head WHERE singleton=1"
            ).fetchone()["event_hash"]
            db.execute("DELETE FROM paca_audit_head WHERE singleton=1")
        try:
            initialized = PostgresPermitStore(DSN, initialize_schema=True)
            self.assertTrue(initialized.verify_audit_chain())
        finally:
            # Keep the shared CI database usable even if the regression fails.
            with self.store._connect() as db:
                db.execute("""
                    INSERT INTO paca_audit_head(singleton,event_hash) VALUES(1,%s)
                    ON CONFLICT(singleton) DO UPDATE SET event_hash=EXCLUDED.event_hash
                """, (original_head,))

    def test_durable_result_and_idempotency_survive_new_store_instance(self):
        permit_id = self.issue()
        calls = []
        result = self.store.execute(
            permit_id, self.action, self.resource, self.request_hash,
            self.policy_version, lambda: calls.append("effect") or {"operation_id": "op-1"},
            idempotency_key=self.idempotency_key,
        )
        reopened = PostgresPermitStore(DSN)
        same_id = reopened.issue(
            self.action, self.resource, self.request_hash, self.policy_version,
            idempotency_key=self.idempotency_key, actor=self.actor,
        )
        result_again = reopened.execute(
            same_id, self.action, self.resource, self.request_hash,
            self.policy_version, lambda: calls.append("duplicate") or {"operation_id": "bad"},
            idempotency_key=self.idempotency_key,
        )
        self.assertEqual(same_id, permit_id)
        self.assertEqual(result_again, result)
        self.assertEqual(calls, ["effect"])
        self.assertTrue(reopened.verify_audit_chain())
        completed = [event for event in reopened.audit_events()
                     if event["event"] == "effect_completed" and event["permit_id"] == permit_id]
        self.assertEqual(completed[-1]["details"]["actor"], self.actor)

    def test_request_fingerprint_must_be_sha256_hex(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.store.issue(
                self.action, self.resource, "invalid", self.policy_version,
                idempotency_key="bad-hash:" + uuid.uuid4().hex,
            )

    def test_audit_chain_detects_deleted_tail_event(self):
        self.issue()
        self.assertTrue(self.store.verify_audit_chain())
        # This suite shares a test database across methods. Restore the row after
        # the assertion so later tests see the original chain and stored head.
        with self.store._connect() as db:
            saved = db.execute("""
                SELECT sequence,event_id,created_at,event,permit_id,action,resource,
                       details_json::text AS details_text,previous_hash,event_hash
                FROM paca_audit WHERE sequence=(SELECT MAX(sequence) FROM paca_audit)
            """).fetchone()
            db.execute("DELETE FROM paca_audit WHERE sequence=%s", (saved["sequence"],))
        self.assertFalse(self.store.verify_audit_chain())
        with self.assertRaisesRegex(HardeningError, "audit head does not match"):
            self.store.record_event("should_not_append", None, None, None, {})
        with self.store._connect() as db:
            db.execute("""
                INSERT INTO paca_audit
                    (sequence,event_id,created_at,event,permit_id,action,resource,
                     details_json,previous_hash,event_hash)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)
            """, (saved["sequence"], saved["event_id"], saved["created_at"], saved["event"],
                  saved["permit_id"], saved["action"], saved["resource"], saved["details_text"],
                  saved["previous_hash"], saved["event_hash"]))
        self.assertTrue(self.store.verify_audit_chain())

    def test_idempotency_key_cannot_be_rebound(self):
        self.issue()
        with self.assertRaises(IdempotencyConflict):
            self.store.issue(
                self.action, self.resource, "f" * 64,
                self.policy_version, idempotency_key=self.idempotency_key,
            )

    def test_stale_state_denies_effect(self):
        permit_id = self.issue()
        self.store.advance_state()
        calls = []
        with self.assertRaisesRegex(PermitRejected, "stale state"):
            self.store.execute(
                permit_id, self.action, self.resource, self.request_hash,
                self.policy_version, lambda: calls.append("unsafe"),
                idempotency_key=self.idempotency_key,
            )
        self.assertEqual(calls, [])
        self.assertTrue(self.store.verify_audit_chain())

    def test_uncertain_effect_is_not_replayed(self):
        permit_id = self.issue()
        def uncertain():
            raise RuntimeError("downstream may have committed")
        with self.assertRaises(EffectOutcomeUnknown):
            self.store.execute(
                permit_id, self.action, self.resource, self.request_hash,
                self.policy_version, uncertain, idempotency_key=self.idempotency_key,
            )
        with self.assertRaises(EffectOutcomeUnknown):
            self.issue()
        self.assertTrue(self.store.verify_audit_chain())

    def test_preprovisioned_schema_can_be_opened_without_ddl_initialization(self):
        store = PostgresPermitStore(DSN, initialize_schema=False)
        self.assertGreaterEqual(store.current_state_version(), 0)

    def test_concurrent_first_use_of_idempotency_key_creates_one_permit(self):
        barrier = threading.Barrier(3)
        permit_ids = []
        errors = []

        def issue():
            try:
                barrier.wait(timeout=3)
                permit_ids.append(self.issue())
            except Exception as exc:
                errors.append(exc)

        first = threading.Thread(target=issue)
        second = threading.Thread(target=issue)
        first.start()
        second.start()
        barrier.wait(timeout=3)
        first.join(6)
        second.join(6)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(permit_ids), 2)
        self.assertEqual(permit_ids[0], permit_ids[1])

    def test_concurrent_claim_runs_effect_at_most_once(self):
        permit_id = self.issue(key=None)
        entered, finish = threading.Event(), threading.Event()
        calls, results, errors = [], [], []

        def effect():
            calls.append("effect")
            entered.set()
            if not finish.wait(5):
                raise RuntimeError("test did not release effect")
            return {"ok": True}

        def invoke(result_list, callback):
            try:
                result_list.append(self.store.execute(
                    permit_id, self.action, self.resource, self.request_hash,
                    self.policy_version, callback,
                ))
            except Exception as exc:
                errors.append(exc)

        first_results, second_results = [], []
        first = threading.Thread(target=invoke, args=(first_results, effect))
        first.start()
        self.assertTrue(entered.wait(3))
        second = threading.Thread(
            target=invoke, args=(second_results, lambda: calls.append("duplicate") or {"bad": True})
        )
        second.start()
        time.sleep(0.1)
        finish.set()
        first.join(6)
        second.join(6)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(calls, ["effect"])
        self.assertEqual(first_results, [{"ok": True}])
        self.assertEqual(second_results, [{"ok": True}])
        self.assertEqual(errors, [])

    def test_state_advance_waits_for_protected_effect_commit(self):
        permit_id = self.issue(key=None)
        entered, finish = threading.Event(), threading.Event()
        milestones, errors = [], []

        def effect():
            milestones.append("effect_started")
            entered.set()
            if not finish.wait(5):
                raise RuntimeError("test did not release effect")
            milestones.append("effect_finished")
            return {"ok": True}

        def run_effect():
            try:
                self.store.execute(permit_id, self.action, self.resource, self.request_hash,
                                   self.policy_version, effect)
            except Exception as exc:
                errors.append(exc)

        def advance():
            try:
                milestones.append(("state_advanced", self.store.advance_state()))
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=run_effect)
        worker.start()
        self.assertTrue(entered.wait(3))
        state_worker = threading.Thread(target=advance)
        state_worker.start()
        time.sleep(0.1)
        finish.set()
        worker.join(6)
        state_worker.join(6)
        self.assertFalse(worker.is_alive())
        self.assertFalse(state_worker.is_alive())
        self.assertEqual(errors, [])
        self.assertLess(milestones.index("effect_finished"),
                        milestones.index(("state_advanced", self.store.current_state_version())))
        self.assertTrue(self.store.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
