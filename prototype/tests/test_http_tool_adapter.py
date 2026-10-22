from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from paca_mvp.gateway import ActionRequest, HTTPJsonActionAdapter, RemoteToolError
from paca_mvp.identity import AuthenticatedPrincipal


class DownstreamHandler(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *args):
        return

    def do_POST(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/elsewhere")
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        type(self).seen.append({
            "body": body,
            "idempotency_key": self.headers.get("Idempotency-Key"),
            "operation_id": self.headers.get("X-PACA-Operation-ID"),
            "authorization": self.headers.get("Authorization"),
        })
        result = json.dumps({"accepted": True, "operation_id": body["operation_id"]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)


class HTTPAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        DownstreamHandler.seen = []
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), DownstreamHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def operation(self):
        return ActionRequest(
            operation_id="a" * 32,
            idempotency_key="idem-adapter-test",
            principal=AuthenticatedPrincipal("user-1", "https://issuer.example", {"sub": "user-1"}),
            action="file.read",
            resource="file:r1",
            arguments={"path": "report.csv"},
            opa_input={"subject": {"id": "user-1"}},
        )

    def test_sends_operation_and_idempotency_binding_to_fixed_endpoint(self):
        adapter = HTTPJsonActionAdapter(
            self.base + "/execute",
            allow_insecure_loopback_for_tests=True,
            service_token_provider=lambda: "service-secret",
        )
        result = adapter(self.operation())
        self.assertEqual(result["accepted"], True)
        seen = DownstreamHandler.seen[-1]
        self.assertEqual(seen["idempotency_key"], self.operation().downstream_idempotency_key)
        self.assertEqual(seen["operation_id"], "a" * 32)
        self.assertEqual(seen["body"]["arguments"], {"path": "report.csv"})
        self.assertEqual(seen["authorization"], "Bearer service-secret")

    def test_redirect_is_not_followed(self):
        adapter = HTTPJsonActionAdapter(
            self.base + "/redirect", allow_insecure_loopback_for_tests=True,
        )
        before = len(DownstreamHandler.seen)
        with self.assertRaises(RemoteToolError):
            adapter(self.operation())
        self.assertEqual(len(DownstreamHandler.seen), before)

    def test_remote_http_requires_explicit_loopback_test_opt_in(self):
        with self.assertRaises(ValueError):
            HTTPJsonActionAdapter("http://example.com/action")


    def test_downstream_idempotency_key_is_scoped_to_verified_principal(self):
        first = self.operation()
        second = ActionRequest(
            operation_id="b" * 32,
            idempotency_key=first.idempotency_key,
            principal=AuthenticatedPrincipal("user-2", first.principal.issuer, {"sub": "user-2"}),
            action=first.action,
            resource=first.resource,
            arguments=first.arguments,
            opa_input=first.opa_input,
        )
        self.assertNotEqual(first.downstream_idempotency_key, second.downstream_idempotency_key)
        self.assertEqual(first.downstream_idempotency_key, self.operation().downstream_idempotency_key)


    def test_preflight_rejects_invalid_downstream_bearer_token(self):
        adapter = HTTPJsonActionAdapter(
            self.base + "/execute",
            allow_insecure_loopback_for_tests=True,
            service_token_provider=lambda: "bad\\r\\nInjected: yes",
        )
        with self.assertRaises(RemoteToolError):
            adapter.preflight()


if __name__ == "__main__":
    unittest.main()
