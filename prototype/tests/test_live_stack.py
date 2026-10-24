from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from paca_mvp.durable import PostgresOperationStore
from paca_mvp.gateway import AuthorizationDenied, HTTPJsonActionAdapter, ProtectedToolGateway
from paca_mvp.identity import AuthenticatedPrincipal, AuthenticationError, TrustedAuthorizationContext
from paca_mvp.opa import OPAPolicyDecisionPoint


OPA_URL = os.environ.get("PACA_OPA_BASE_URL")
DATABASE_DSN = os.environ.get("PACA_TEST_RUNTIME_DATABASE_URL")


@unittest.skipUnless(
    OPA_URL and DATABASE_DSN,
    "Set PACA_OPA_BASE_URL and PACA_TEST_RUNTIME_DATABASE_URL for full-stack integration tests",
)
class LiveEnforcementStackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pdp = OPAPolicyDecisionPoint(base_url=OPA_URL)
        cls.pdp.preflight()
        cls.store = PostgresOperationStore(DATABASE_DSN, initialize_schema=False)
        cls.store.check_ready()

    def setUp(self):
        self.downstream_requests = []
        capture = self.downstream_requests

        class DownstreamHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                request_body = json.loads(self.rfile.read(length))
                capture.append({
                    "path": self.path,
                    "headers": dict(self.headers),
                    "body": request_body,
                })
                response_body = json.dumps({
                    "ok": True,
                    "path": request_body["arguments"]["path"],
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response_body)))
                self.end_headers()
                self.wfile.write(response_body)

            def log_message(self, _format, *_args):
                return

        self.downstream = ThreadingHTTPServer(("127.0.0.1", 0), DownstreamHandler)
        self.downstream_thread = threading.Thread(target=self.downstream.serve_forever, daemon=True)
        self.downstream_thread.start()
        endpoint = f"http://127.0.0.1:{self.downstream.server_address[1]}/v1/read"
        adapter = HTTPJsonActionAdapter(
            endpoint,
            service_token_provider=lambda: "test-downstream-service-token",
            allow_insecure_loopback_for_tests=True,
        )

        class Authenticator:
            def authenticate(_self, header):
                if header != "Bearer signed-test-token":
                    raise AuthenticationError("invalid test token")
                return AuthenticatedPrincipal(
                    "user-1",
                    "https://identity.example",
                    {"sub": "user-1"},
                )

        class ContextProvider:
            resources = {
                "file:r1": {
                    "owner_id": "user-1",
                    "tenant_id": "tenant-1",
                    "canonical_path": "reports/q1.csv",
                },
                "file:r2": {
                    "owner_id": "user-2",
                    "tenant_id": "tenant-1",
                    "canonical_path": "secrets.csv",
                },
                "file:tenant2": {
                    "owner_id": "user-1",
                    "tenant_id": "tenant-2",
                    "canonical_path": "reports/other-tenant.csv",
                },
            }

            def load(_self, principal, action, resource, arguments):
                attrs = dict(self.resources.get(resource, {}))
                return TrustedAuthorizationContext(
                    subject_attributes={
                        "status": "active",
                        "role": "analyst",
                        "tenant_id": "tenant-1",
                    },
                    resource_attributes=attrs,
                    environment={"test": True},
                )

        self.gateway = ProtectedToolGateway(
            authenticator=Authenticator(),
            context_provider=ContextProvider(),
            policy_decision_point=self.pdp,
            operation_store=self.store,
            permit_ttl_seconds=15,
        )
        self.gateway.register_action("file.read", adapter)

    def tearDown(self):
        self.downstream.shutdown()
        self.downstream.server_close()
        self.downstream_thread.join(timeout=3)

    def execute(self, *, key=None, resource="file:r1", path="reports/q1.csv"):
        return self.gateway.execute(
            "Bearer signed-test-token",
            action="file.read",
            resource=resource,
            arguments={"path": path},
            idempotency_key=key or ("live-" + uuid.uuid4().hex),
        )

    def test_real_opa_postgres_gateway_and_http_adapter_work_together(self):
        key = "live-replay-" + uuid.uuid4().hex
        first = self.execute(key=key)
        replay = self.execute(key=key)

        self.assertEqual(first.status, "succeeded")
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(first.operation_id, replay.operation_id)
        self.assertEqual(first.result, {"ok": True, "path": "reports/q1.csv"})
        self.assertEqual(len(self.downstream_requests), 1)

        request = self.downstream_requests[0]
        self.assertEqual(request["path"], "/v1/read")
        self.assertEqual(request["body"]["action"], "file.read")
        self.assertEqual(request["body"]["resource"], "file:r1")
        self.assertEqual(request["body"]["arguments"], {"path": "reports/q1.csv"})
        self.assertEqual(request["headers"]["Authorization"], "Bearer test-downstream-service-token")
        downstream_key = request["headers"]["Idempotency-Key"]
        self.assertRegex(downstream_key, r"^[0-9a-f]{64}$")
        self.assertNotEqual(downstream_key, key)
        self.assertEqual(request["headers"]["X-PACA-Operation-ID"], first.operation_id)
        self.assertTrue(self.store.verify_audit_chain())

    def test_real_policy_denials_do_not_dispatch_to_downstream(self):
        denied_requests = (
            {"resource": "file:r1", "path": "secrets.csv"},
            {"resource": "file:r2", "path": "secrets.csv"},
            {"resource": "file:tenant2", "path": "reports/other-tenant.csv"},
        )
        for request in denied_requests:
            with self.subTest(request=request):
                before = len(self.downstream_requests)
                with self.assertRaises(AuthorizationDenied):
                    self.execute(**request)
                self.assertEqual(len(self.downstream_requests), before)
        self.assertTrue(self.store.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
