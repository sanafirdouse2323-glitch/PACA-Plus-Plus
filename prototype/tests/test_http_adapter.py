from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest

from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from paca_mvp.gateway import ActionRequest, HTTPJsonActionAdapter, RemoteToolError
from paca_mvp.identity import AuthenticatedPrincipal


class HTTPActionAdapterTests(unittest.TestCase):
    def setUp(self):
        self.mode = {"value": "ok"}
        self.received = []
        self.redirect_hits = []
        mode = self.mode
        received = self.received
        redirect_hits = self.redirect_hits

        class SinkHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                redirect_hits.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, _format, *_args):
                return

        self.sink = ThreadingHTTPServer(("127.0.0.1", 0), SinkHandler)
        self.sink_thread = threading.Thread(target=self.sink.serve_forever, daemon=True)
        self.sink_thread.start()

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                received.append({
                    "path": self.path,
                    "headers": dict(self.headers),
                    "body": body,
                })
                if mode["value"] == "redirect":
                    self.send_response(307)
                    self.send_header(
                        "Location",
                        f"http://127.0.0.1:{sink.server_address[1]}/redirected",
                    )
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if mode["value"] == "duplicate-json":
                    response_body = b'{"ok":false,"ok":true}'
                elif mode["value"] == "non-finite-json":
                    response_body = b'{"ok":NaN}'
                else:
                    response_body = b'{"ok":true,"result":"test"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response_body)))
                self.end_headers()
                self.wfile.write(response_body)

            def log_message(self, _format, *_args):
                return

        sink = self.sink
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        endpoint = f"http://127.0.0.1:{self.server.server_address[1]}/fixed/action"
        self.adapter = HTTPJsonActionAdapter(
            endpoint,
            service_token_provider=lambda: "trusted-downstream-token",
            allow_insecure_loopback_for_tests=True,
        )

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.sink.shutdown()
        self.sink.server_close()
        self.sink_thread.join(timeout=3)

    @staticmethod
    def request():
        principal = AuthenticatedPrincipal(
            "user-1", "https://identity.example", {"sub": "user-1"}
        )
        return ActionRequest(
            operation_id="a" * 32,
            idempotency_key="client-request-17",
            principal=principal,
            action="file.read",
            resource="file:r1",
            arguments={"path": "reports/q1.csv"},
            opa_input={"action": "file.read"},
        )

    def test_adapter_posts_to_fixed_endpoint_with_service_identity_and_deduplication_key(self):
        result = self.adapter(self.request())
        self.assertEqual(result, {"ok": True, "result": "test"})
        self.assertEqual(len(self.received), 1)
        request = self.received[0]
        self.assertEqual(request["path"], "/fixed/action")
        self.assertEqual(request["headers"]["Authorization"], "Bearer trusted-downstream-token")
        self.assertEqual(request["headers"]["X-PACA-Operation-ID"], "a" * 32)
        self.assertRegex(request["headers"]["Idempotency-Key"], r"^[0-9a-f]{64}$")
        self.assertNotEqual(request["headers"]["Idempotency-Key"], "client-request-17")
        body = json.loads(request["body"])
        self.assertEqual(body["action"], "file.read")
        self.assertEqual(body["arguments"], {"path": "reports/q1.csv"})

    def test_adapter_rejects_redirects_without_forwarding_credentials(self):
        self.mode["value"] = "redirect"
        with self.assertRaisesRegex(RemoteToolError, "downstream_http_status_307"):
            self.adapter(self.request())
        self.assertEqual(self.redirect_hits, [])

    def test_adapter_rejects_duplicate_keys_and_non_finite_json_responses(self):
        for mode in ("duplicate-json", "non-finite-json"):
            with self.subTest(mode=mode):
                self.mode["value"] = mode
                with self.assertRaises(RemoteToolError):
                    self.adapter(self.request())


if __name__ == "__main__":
    unittest.main()
