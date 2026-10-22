from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import tempfile
import threading
import unittest
import uuid
from pathlib import Path

from paca_mvp.durable import (
    IdempotencyConflict,
    OperationStateError,
    SQLiteOperationStore,
)
from paca_mvp.gateway import (
    AuthorizationDenied,
    ContextChanged,
    OperationOutcomeUnresolved,
    PolicyEvaluationFailed,
    ProtectedToolGateway,
)
from paca_mvp.identity import (
    AuthenticatedPrincipal,
    AuthenticationError,
    TrustedAuthorizationContext,
)
from paca_mvp.opa import OPAError, OPADecision


class FakeAuthenticator:
    def authenticate(self, header):
        if header != "Bearer valid-token":
            raise AuthenticationError("bad_token")
        return AuthenticatedPrincipal("u1", "https://identity.example", {"sub": "u1"})


class ContextFixture:
    def __init__(self, variants=None):
        self.variants = list(variants or [self.normal()])
        self.calls = 0
        self.lock = threading.Lock()

    @staticmethod
    def normal(role="analyst"):
        return TrustedAuthorizationContext(
            subject_attributes={"status": "active", "role": role, "tenant_id": "t1"},
            resource_attributes={"owner_id": "u1", "tenant_id": "t1"},
            environment={},
        )

    def load(self, principal, action, resource, arguments):
        with self.lock:
            index = min(self.calls, len(self.variants) - 1)
            self.calls += 1
            value = self.variants[index]
        return value


class FakeOPA:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []

    def evaluate(self, value):
        self.calls.append(value)
        if self.fail:
            raise OPAError("test unavailable")
        subject = value.get("subject", {})
        resource = value.get("resource", {})
        allowed = (
            subject.get("status") == "active"
            and value.get("action") == "file.read"
            and subject.get("role") == "analyst"
            and subject.get("id") == resource.get("owner_id")
            and subject.get("tenant_id") == resource.get("tenant_id")
        )
        result = {"allow": allowed, "reason": "permitted" if allowed else "no_matching_permit"}
        return OPADecision(allowed, result["reason"], result, decision_id=f"fake-decision-{len(self.calls)}")


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLiteOperationStore(str(Path(self.temp.name) / "gateway.db"))
        self.context = ContextFixture()
        self.opa = FakeOPA()
        self.effects = []
        self.gateway = ProtectedToolGateway(
            authenticator=FakeAuthenticator(),
            context_provider=self.context,
            policy_decision_point=self.opa,
            operation_store=self.store,
        )
        self.gateway.register_action("file.read", lambda request: (
            self.effects.append((request.operation_id, request.arguments["path"])) or
            {"content": "fixture", "path": request.arguments["path"]}
        ))

    def tearDown(self):
        self.temp.cleanup()

    def call(self, key=None, args=None):
        return self.gateway.execute(
            "Bearer valid-token", action="file.read", resource="file:r1",
            arguments=args or {"path": "report.csv"},
            idempotency_key=key or ("idem-" + uuid.uuid4().hex),
        )

    def test_authorized_call_then_safe_idempotent_replay(self):
        key = "idem-" + uuid.uuid4().hex
        first = self.call(key=key)
        replay = self.call(key=key)
        self.assertEqual(first.status, "succeeded")
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(first.operation_id, replay.operation_id)
        self.assertEqual(len(self.effects), 1)
        self.assertGreaterEqual(len(self.opa.calls), 3)
        stored = self.store.get_operation(first.operation_id)
        self.assertEqual(stored.policy_decision["decision_id"], "fake-decision-2")
        self.assertTrue(self.store.verify_audit_chain())

    def test_key_reuse_with_other_arguments_is_rejected(self):
        key = "idem-" + uuid.uuid4().hex
        self.call(key=key)
        with self.assertRaises(IdempotencyConflict):
            self.call(key=key, args={"path": "secret.csv"})
        self.assertEqual(len(self.effects), 1)

    def test_policy_denial_never_calls_handler(self):
        self.context = ContextFixture([ContextFixture.normal(role="guest")])
        self.gateway.context_provider = self.context
        with self.assertRaises(AuthorizationDenied):
            self.call()
        self.assertEqual(self.effects, [])
        self.assertTrue(self.store.verify_audit_chain())

    def test_context_change_between_initial_check_and_dispatch_cancels_operation(self):
        self.context = ContextFixture([
            ContextFixture.normal(),
            ContextFixture.normal(role="guest"),
        ])
        self.gateway.context_provider = self.context
        with self.assertRaises(ContextChanged):
            self.call()
        self.assertEqual(self.effects, [])
        self.assertTrue(self.store.verify_audit_chain())

    def test_opa_unavailable_fails_closed(self):
        self.opa.fail = True
        with self.assertRaises(PolicyEvaluationFailed):
            self.call()
        self.assertEqual(self.effects, [])
        self.assertTrue(self.store.verify_audit_chain())

    def test_authentication_failure_never_calls_handler(self):
        with self.assertRaises(PermissionError):
            self.gateway.execute(
                "Bearer invalid", action="file.read", resource="file:r1",
                arguments={}, idempotency_key="idem-" + uuid.uuid4().hex,
            )
        self.assertEqual(self.effects, [])

    def test_effect_exception_becomes_unknown_not_automatic_retry(self):
        failing_gateway = ProtectedToolGateway(
            authenticator=FakeAuthenticator(), context_provider=ContextFixture(),
            policy_decision_point=FakeOPA(), operation_store=self.store,
        )
        attempts = []
        def ambiguous(_request):
            attempts.append("called")
            raise TimeoutError("connection timed out after request was sent")
        failing_gateway.register_action("file.read", ambiguous)
        key = "idem-" + uuid.uuid4().hex
        with self.assertRaises(OperationOutcomeUnresolved) as caught:
            failing_gateway.execute(
                "Bearer valid-token", action="file.read", resource="file:r1",
                arguments={"path": "report.csv"}, idempotency_key=key,
            )
        self.assertIsNotNone(caught.exception.operation_id)
        record = self.store.get_operation(caught.exception.operation_id)
        self.assertEqual(record.status, "unknown")
        with self.assertRaises(OperationOutcomeUnresolved):
            failing_gateway.execute(
                "Bearer valid-token", action="file.read", resource="file:r1",
                arguments={"path": "report.csv"}, idempotency_key=key,
            )
        self.assertEqual(attempts, ["called"])

    def test_concurrent_duplicate_key_never_dispatches_twice(self):
        key = "idem-" + uuid.uuid4().hex
        results, errors = [], []
        gate = threading.Barrier(2)
        def worker():
            gate.wait()
            try:
                results.append(self.call(key=key))
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(len(results) + len(errors), 2)

    def test_operation_status_is_restricted_to_initiating_principal(self):
        result = self.call()
        status = self.gateway.get_operation_status("Bearer valid-token", result.operation_id)
        self.assertEqual(status["status"], "succeeded")
        other = FakeAuthenticator()
        other.authenticate = lambda _header: AuthenticatedPrincipal(
            "u2", "https://identity.example", {"sub": "u2"}
        )
        self.gateway.authenticator = other
        with self.assertRaises(LookupError):
            self.gateway.get_operation_status("Bearer valid-token", result.operation_id)


    def test_same_client_idempotency_key_is_independent_across_principals(self):
        key = "idem-shared-" + uuid.uuid4().hex
        first = self.call(key=key)

        class OtherPrincipalAuth:
            def authenticate(self, header):
                if header != "Bearer valid-token":
                    raise AuthenticationError("bad_token")
                return AuthenticatedPrincipal("u2", "https://identity.example", {"sub": "u2"})

        other = ProtectedToolGateway(
            authenticator=OtherPrincipalAuth(),
            context_provider=ContextFixture([
                TrustedAuthorizationContext(
                    subject_attributes={"status": "active", "role": "analyst", "tenant_id": "t1"},
                    resource_attributes={"owner_id": "u2", "tenant_id": "t1"},
                    environment={},
                )
            ]),
            policy_decision_point=FakeOPA(),
            operation_store=self.store,
        )
        other.register_action("file.read", lambda request: {"user": request.principal.subject})
        second = other.execute(
            "Bearer valid-token", action="file.read", resource="file:r1",
            arguments={"path": "report.csv"}, idempotency_key=key,
        )
        self.assertNotEqual(first.operation_id, second.operation_id)
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(second.result, {"user": "u2"})
        self.assertTrue(self.store.verify_audit_chain())


    def test_issued_operation_can_resume_if_interrupted_before_claim(self):
        key = "idem-" + uuid.uuid4().hex
        original_claim = self.store.claim
        fail_once = {"value": True}

        def injected_preclaim_failure(operation_id, **kwargs):
            if fail_once["value"]:
                fail_once["value"] = False
                raise RuntimeError("simulated failure before state transition")
            return original_claim(operation_id, **kwargs)

        self.store.claim = injected_preclaim_failure
        with self.assertRaisesRegex(RuntimeError, "before state transition"):
            self.call(key=key)
        self.assertEqual(self.effects, [])
        self.store.claim = original_claim

        result = self.call(key=key)
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(len(self.effects), 1)
        self.assertTrue(self.store.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
