from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.error import URLError
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from paca_mvp.hardening import (
    ContextUnavailable, EffectOutcomeUnknown, GuardedGateway, IdempotencyConflict,
    OPAClient, PermitRejected, PolicyUnavailable, SQLitePermitStore, TrustedPrincipal,
)
from paca_mvp.providers import (
    FilesystemToolAdapter, HTTPAuthorizationContextProvider, HTTPJSONToolAdapter,
    HTTPRoute, ToolInvocationError,
)


class FakeResponse:
    def __init__(self, payload: dict, status: int = 200):
        self.status = status
        self.data = json.dumps(payload).encode()

    def read(self, size: int = -1) -> bytes:
        return self.data[:size]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class OPAClientTests(unittest.TestCase):
    def test_named_decision_accepts_only_explicit_boolean(self):
        client = OPAClient("http://127.0.0.1:8181")
        with patch("paca_mvp.hardening._urlopen_no_redirect", return_value=FakeResponse({
            "result": {"allow": True, "policy_version": "v1", "reason": "unit-test"}
        })) as mocked:
            decision = client.decide({"action": "file.read"})
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["policy_version"], "v1")
        self.assertTrue(mocked.call_args.args[0].full_url.endswith("/v1/data/paca/authz/decision"))
        sent = json.loads(mocked.call_args.args[0].data.decode())
        self.assertEqual(sent, {"input": {"action": "file.read"}})

    def test_missing_allow_or_permit_version_fails_closed(self):
        client = OPAClient("http://127.0.0.1:8181")
        for payload in ({"result": {}}, {"result": {"allow": True}},
                        {"result": {"allow": "true", "policy_version": "v1"}}):
            with self.subTest(payload=payload), patch(
                "paca_mvp.hardening.urlopen", return_value=FakeResponse(payload)
            ):
                with self.assertRaises(PolicyUnavailable):
                    client.decide({"action": "file.read"})

    def test_active_policy_version_is_retrieved_and_required(self):
        client = OPAClient("http://127.0.0.1:8181")
        with patch("paca_mvp.hardening._urlopen_no_redirect",
                   return_value=FakeResponse({"result": "v2"})) as mocked:
            self.assertEqual(client.get_policy_version(), "v2")
            self.assertTrue(mocked.call_args.args[0].full_url.endswith("/v1/data/paca/authz/policy_version"))
        with patch("paca_mvp.hardening._urlopen_no_redirect",
                   return_value=FakeResponse({"result": None})):
            with self.assertRaises(PolicyUnavailable):
                client.get_policy_version()

    def test_custom_decision_path_uses_matching_version_path(self):
        client = OPAClient(
            "https://opa.example", decision_path="/v1/data/team/paca/decision"
        )
        with patch("paca_mvp.hardening._urlopen_no_redirect",
                   return_value=FakeResponse({"result": "v3"})) as mocked:
            self.assertEqual(client.get_policy_version(), "v3")
        self.assertTrue(mocked.call_args.args[0].full_url.endswith("/v1/data/team/paca/policy_version"))
        with self.assertRaises(ValueError):
            OPAClient("https://opa.example", decision_path="/v1/data/team/paca")

    def test_request_size_and_non_json_values_fail_closed(self):
        client = OPAClient("http://127.0.0.1:8181", max_request_bytes=10)
        with self.assertRaises(PolicyUnavailable):
            client.decide({"action": "file.read"})
        with self.assertRaises(PolicyUnavailable):
            OPAClient("http://127.0.0.1:8181").decide({"number": float("nan")})

    def test_network_failure_fails_closed(self):
        with patch("paca_mvp.hardening._urlopen_no_redirect", side_effect=URLError("offline")):
            with self.assertRaises(PolicyUnavailable):
                OPAClient("http://127.0.0.1:8181").decide({"action": "file.read"})


class DurableStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "state" / "paca.sqlite3")
        self.store = SQLitePermitStore(self.path)
        self.request_hash = "a" * 64
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def tearDown(self):
        self.temp.cleanup()

    def issue(self, key="request-1", actor=None):
        return self.store.issue("file.write", "file:report-1", self.request_hash,
                                "policy-v1", idempotency_key=key, actor=actor)

    def test_durability_and_idempotent_replay_after_reopen(self):
        actor = {"subject": "user-17", "issuer": "https://issuer.example", "audience": "paca-api"}
        permit_id = self.issue(actor=actor)
        calls = []
        result = self.store.execute(permit_id, "file.write", "file:report-1",
                                    self.request_hash, "policy-v1",
                                    lambda: calls.append("once") or {"written": True},
                                    idempotency_key="request-1")
        reopened = SQLitePermitStore(self.path)
        same_id = reopened.issue("file.write", "file:report-1", self.request_hash,
                                 "policy-v1", idempotency_key="request-1")
        result2 = reopened.execute(same_id, "file.write", "file:report-1",
                                   self.request_hash, "policy-v1",
                                   lambda: calls.append("duplicate") or {"written": False},
                                   idempotency_key="request-1")
        self.assertEqual(permit_id, same_id)
        self.assertEqual(result, result2)
        self.assertEqual(calls, ["once"])
        events = reopened.audit_events()
        issue_event = next(event for event in events if event["event"] == "permit_issued")
        completed_event = next(event for event in events if event["event"] == "effect_completed")
        self.assertEqual(issue_event["details"]["actor"], actor)
        self.assertEqual(completed_event["details"]["actor"], actor)
        self.assertTrue(reopened.verify_audit_chain())

    def test_same_idempotency_key_cannot_be_rebound_to_another_request(self):
        self.issue()
        with self.assertRaises(IdempotencyConflict):
            self.store.issue("file.write", "file:report-1", "b" * 64,
                             "policy-v1", idempotency_key="request-1")

    def test_stale_state_invalidates_permit_and_audits_rejection(self):
        permit_id = self.issue()
        self.store.advance_state()
        calls = []
        with self.assertRaisesRegex(PermitRejected, "stale state"):
            self.store.execute(permit_id, "file.write", "file:report-1",
                               self.request_hash, "policy-v1",
                               lambda: calls.append("should-not-run"),
                               idempotency_key="request-1")
        self.assertEqual(calls, [])
        self.assertEqual(self.store.audit_events()[-1]["event"], "permit_rejected")
        self.assertTrue(self.store.verify_audit_chain())

    def test_stale_policy_invalidates_permit(self):
        permit_id = self.issue()
        with self.assertRaisesRegex(PermitRejected, "stale policy"):
            self.store.execute(permit_id, "file.write", "file:report-1",
                               self.request_hash, "policy-v2", lambda: "unsafe",
                               idempotency_key="request-1")
        self.assertTrue(self.store.verify_audit_chain())

    def test_effect_exception_is_unknown_and_never_retried_automatically(self):
        permit_id = self.issue()
        with self.assertRaises(EffectOutcomeUnknown):
            self.store.execute(permit_id, "file.write", "file:report-1",
                               self.request_hash, "policy-v1",
                               lambda: (_ for _ in ()).throw(RuntimeError("possibly partial")),
                               idempotency_key="request-1")
        with self.assertRaises(EffectOutcomeUnknown):
            self.store.issue("file.write", "file:report-1", self.request_hash,
                             "policy-v1", idempotency_key="request-1")
        self.assertTrue(self.store.verify_audit_chain())

    def test_crash_recovery_marks_claimed_effect_unknown_not_replayable(self):
        permit_id = self.issue()
        with self.store._connect() as db:
            db.execute("UPDATE permits SET status='executing' WHERE permit_id=?", (permit_id,))
            db.execute("UPDATE idempotency SET status='executing' WHERE idempotency_key='request-1'")
        self.assertEqual(self.store.mark_unknown_operations_for_reconciliation(), 1)
        with self.assertRaises(EffectOutcomeUnknown):
            self.store.execute(permit_id, "file.write", "file:report-1",
                               self.request_hash, "policy-v1", lambda: "duplicate",
                               idempotency_key="request-1")

    def test_audit_hash_chain_detects_edit(self):
        self.issue()
        self.assertTrue(self.store.verify_audit_chain())
        with self.store._connect() as db:
            db.execute("UPDATE audit SET details_json='{}' WHERE sequence=1")
        self.assertFalse(self.store.verify_audit_chain())

    def test_concurrent_attempts_never_call_effect_twice(self):
        permit_id = self.store.issue("file.write", "file:report-1", self.request_hash,
                                     "policy-v1", idempotency_key=None)
        entered, finish = threading.Event(), threading.Event()
        calls, errors = [], []

        def effect():
            calls.append("called")
            entered.set()
            finish.wait(2)
            return {"ok": True}

        def first():
            try:
                self.store.execute(permit_id, "file.write", "file:report-1",
                                   self.request_hash, "policy-v1", effect)
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=first)
        thread.start()
        self.assertTrue(entered.wait(2))
        with self.assertRaises(EffectOutcomeUnknown):
            self.store.execute(permit_id, "file.write", "file:report-1",
                               self.request_hash, "policy-v1",
                               lambda: calls.append("duplicate"))
        finish.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(calls, ["called"])
        self.assertEqual(errors, [])

    def test_expired_permit_is_not_executed(self):
        permit = self.store.issue("file.write", "file:report-1", self.request_hash,
                                  "policy-v1", ttl_seconds=0.001)
        time.sleep(0.02)
        calls = []
        with self.assertRaisesRegex(PermitRejected, "expired"):
            self.store.execute(permit, "file.write", "file:report-1",
                               self.request_hash, "policy-v1", lambda: calls.append(1))
        self.assertEqual(calls, [])


class ProviderAndGatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLitePermitStore(str(Path(self.temp.name) / "gateway.sqlite3"))
        self.principal = TrustedPrincipal(
            subject="user-17", issuer="https://issuer.example", audience="paca-api",
            claims={"sub": "user-17", "role": "analyst", "suspended": False},
            authenticated_at="2026-01-01T00:00:00+00:00",
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_context_endpoint_requires_tls_and_strong_service_token(self):
        with self.assertRaises(ValueError):
            HTTPAuthorizationContextProvider("http://context.example", "x" * 20)
        with self.assertRaises(ValueError):
            HTTPAuthorizationContextProvider("https://context.example", "short")

    def test_trusted_context_cannot_override_authenticated_identity(self):
        principal = self.principal
        class IdP:
            def authenticate(self, credential):
                return principal
        class Context:
            def get_context(self, *args):
                return {"identity": {"subject": "attacker"}}
        class OPA:
            def decide(self, request):
                return {"allowed": True, "policy_version": "v1", "reason": "test"}
        class Adapter:
            def invoke(self, *args):
                raise AssertionError("must not execute")
        gateway = GuardedGateway(OPA(), self.store, IdP(), Context())
        with self.assertRaises(ContextUnavailable):
            gateway.authorize_and_execute("credential", "file.read", "file:report-1",
                                          {}, Adapter(), "idem-1")

    def test_gateway_composes_verified_identity_opa_durable_permit_and_adapter(self):
        captured = {}
        principal = self.principal
        class IdP:
            def authenticate(self, credential):
                self.assertion = credential
                return principal
        class Context:
            def get_context(self, got, action, resource):
                self.got = got
                return {"authorization": {"role": "analyst"},
                        "resource": {"owner": "user-17"}}
        class OPA:
            def decide(self, request):
                captured["request"] = request
                return {"allowed": True, "policy_version": "v1", "reason": "permitted"}
            def get_policy_version(self):
                return "v1"
        class Adapter:
            def invoke(self, action, resource, arguments, idempotency_key):
                captured["effect"] = (action, resource, dict(arguments), idempotency_key)
                return {"ok": True}
        adapter = Adapter()
        gateway = GuardedGateway(OPA(), self.store, IdP(), Context())
        result = gateway.authorize_and_execute("valid-token", "file.write", "file:report-1",
                                               {"content": "safe"}, adapter, "idem-2")
        self.assertEqual(result, {"ok": True})
        self.assertEqual(captured["request"]["principal"]["subject"], "user-17")
        self.assertEqual(captured["request"]["context"]["identity"]["subject"], "user-17")
        self.assertEqual(captured["effect"], ("file.write", "file:report-1", {"content": "safe"}, "idem-2"))
        self.assertTrue(self.store.verify_audit_chain())


class AdapterTests(unittest.TestCase):
    def test_filesystem_adapter_confines_logical_resources_and_effects(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            (root / "docs").mkdir(parents=True)
            adapter = FilesystemToolAdapter(str(root), {"file:report-1": "docs/report.txt"})
            self.assertEqual(adapter.invoke("file.write", "file:report-1",
                                             {"content": "protected report"}, "write-1"),
                             {"bytes_written": len("protected report")})
            self.assertEqual(adapter.invoke("file.read", "file:report-1", {}, "read-1"),
                             {"content": "protected report"})
            with self.assertRaises(ToolInvocationError):
                adapter.invoke("file.read", "../secret", {}, "bad-1")
            self.assertEqual(adapter.invoke("file.delete", "file:report-1", {}, "delete-1"),
                             {"deleted": True})

    def test_filesystem_adapter_refuses_symlink_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            outside = Path(temp) / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "secret.txt").write_text("no", encoding="utf-8")
            (root / "linked").symlink_to(outside, target_is_directory=True)
            adapter = FilesystemToolAdapter(str(root), {"file:secret": "linked/secret.txt"})
            with self.assertRaises(ToolInvocationError):
                adapter.invoke("file.read", "file:secret", {}, "read-2")

    def test_http_adapter_uses_only_configured_route_and_idempotency_header(self):
        adapter = HTTPJSONToolAdapter(
            "https://api.example",
            {("ticket.create", "ticket:123"): HTTPRoute("POST", "/v1/tickets")},
            bearer_token="service-secret",
        )
        response = FakeResponse({"ticket_id": "t-1"})
        with patch("paca_mvp.providers._urlopen_no_redirect", return_value=response) as mocked:
            result = adapter.invoke("ticket.create", "ticket:123", {"title": "Hi"}, "idem-3")
        self.assertEqual(result, {"ticket_id": "t-1"})
        request = mocked.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.example/v1/tickets")
        self.assertEqual(request.get_header("Idempotency-key"), "idem-3")
        with self.assertRaises(ToolInvocationError):
            adapter.invoke("ticket.delete", "ticket:123", {}, "idem-4")


if __name__ == "__main__":
    unittest.main()
