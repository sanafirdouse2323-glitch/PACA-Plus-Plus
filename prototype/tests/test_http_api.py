from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import json
import socket
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from paca_mvp.durable import SQLiteOperationStore
from paca_mvp.gateway import ProtectedToolGateway
from paca_mvp.http_api import make_server
from paca_mvp.identity import AuthenticatedPrincipal, TrustedAuthorizationContext
from paca_mvp.opa import OPADecision


class Auth:
    def authenticate(self, header):
        if header != "Bearer valid":
            raise ValueError("not authenticated")
        return AuthenticatedPrincipal("u1", "https://id.example", {"sub": "u1"})


class Context:
    def load(self, principal, action, resource, arguments):
        return TrustedAuthorizationContext(
            subject_attributes={"role": "analyst", "status": "active", "tenant_id": "t1", "user_id": "db-u1"},
            resource_attributes={"owner_id": "db-u1", "tenant_id": "t1"},
            environment={},
        )


class PDP:
    def evaluate(self, value):
        allow = value["action"] == "file.read" and value["resource"].get("owner_id") == value["subject"].get("user_id")
        return OPADecision(allow, "permitted" if allow else "no_matching_permit",
                           {"allow": allow, "reason": "permitted" if allow else "no_matching_permit"})


class HttpApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLiteOperationStore(str(Path(self.temp.name) / "http.db"))
        self.effects = []
        self.gateway = ProtectedToolGateway(
            authenticator=Auth(), context_provider=Context(), policy_decision_point=PDP(),
            operation_store=self.store,
        )
        self.gateway.register_action("file.read", lambda op: (
            self.effects.append(op.arguments["path"]) or {"path": op.arguments["path"], "ok": True}
        ))
        self.server = make_server(self.gateway, host="127.0.0.1", port=0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.temp.cleanup()

    def post(self, body, key=None):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/v1/execute",
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer valid",
                "Idempotency-Key": key or ("idem-" + uuid.uuid4().hex),
            },
            method="POST",
        )
        return urllib.request.urlopen(req, timeout=3)

    def test_protected_api_executes_and_supports_status_lookup(self):
        with self.post({"action": "file.read", "resource": "file:r1",
                        "arguments": {"path": "report.csv"}}) as response:
            payload = json.loads(response.read())
        self.assertEqual(payload["status"], "succeeded")
        self.assertEqual(payload["result"], {"path": "report.csv", "ok": True})
        self.assertEqual(self.effects, ["report.csv"])

        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/v1/operations/{payload['operation_id']}",
            headers={"Authorization": "Bearer valid"},
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            status = json.loads(response.read())
        self.assertEqual(status["status"], "succeeded")
        self.assertNotIn("result", status)

    def test_request_cannot_supply_context_or_handler(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.post({"action": "file.read", "resource": "file:r1",
                       "arguments": {}, "context": {"role": "admin"}})
        self.assertEqual(caught.exception.code, 400)
        self.assertEqual(self.effects, [])

    def test_policy_denial_is_http_403_and_has_no_effect(self):
        self.gateway.register_action("file.secret", lambda _op: self.effects.append("secret"))
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.post({"action": "file.secret", "resource": "file:r1", "arguments": {}})
        self.assertEqual(caught.exception.code, 403)
        self.assertEqual(self.effects, [])


    def test_ambiguous_json_and_duplicate_auth_headers_are_rejected(self):
        def send_raw(body, key, extra_headers=""):
            headers = (
                "POST /v1/execute HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Authorization: Bearer valid\r\n"
                f"Idempotency-Key: {key}\r\n"
                + extra_headers
                + "Connection: close\r\n\r\n"
            ).encode("ascii") + body
            with socket.create_connection(("127.0.0.1", self.port), timeout=3) as client:
                client.sendall(headers)
                response = bytearray()
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    response.extend(chunk)
            return bytes(response)

        duplicate_key = (
            b'{"action":"file.read","action":"file.delete",'
            b'"resource":"file:r1","arguments":{"path":"x"}}'
        )
        non_finite = b'{"action":"file.read","resource":"file:r1","arguments":{"path":NaN}}'
        valid = b'{"action":"file.read","resource":"file:r1","arguments":{"path":"report.csv"}}'

        for body in (duplicate_key, non_finite):
            with self.subTest(body=body):
                response = send_raw(body, "strict-" + uuid.uuid4().hex)
                self.assertIn(b"400 Bad Request", response)
                self.assertIn(b"invalid_json", response)

        response = send_raw(
            valid, "strict-" + uuid.uuid4().hex,
            extra_headers="Authorization: Bearer attacker\r\n",
        )
        self.assertIn(b"400 Bad Request", response)
        self.assertIn(b"duplicate_authorization_header", response)

        response = send_raw(
            valid, "strict-" + uuid.uuid4().hex,
            extra_headers="Idempotency-Key: attacker-key\r\n",
        )
        self.assertIn(b"400 Bad Request", response)
        self.assertIn(b"idempotency_key_header_required_once", response)
        self.assertEqual(self.effects, [])

    def test_duplicate_content_length_is_rejected_before_authorization_or_effect(self):
        request = (
            "POST /v1/execute HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 2\r\n"
            "Content-Length: 2\r\n"
            "Authorization: Bearer valid\r\n"
            "Idempotency-Key: duplicate-length-test\r\n"
            "Connection: close\r\n\r\n{}"
        ).encode("ascii")
        with socket.create_connection(("127.0.0.1", self.port), timeout=3) as client:
            client.sendall(request)
            response = bytearray()
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
        self.assertIn(b"400 Bad Request", response)
        self.assertIn(b"invalid_content_length", response)
        self.assertEqual(self.effects, [])


if __name__ == "__main__":
    unittest.main()
