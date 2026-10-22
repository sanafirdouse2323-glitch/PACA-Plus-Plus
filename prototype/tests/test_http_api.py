import json
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
            subject_attributes={"role": "analyst", "status": "active", "tenant_id": "t1"},
            resource_attributes={"owner_id": "u1", "tenant_id": "t1"},
            environment={},
        )


class PDP:
    def evaluate(self, value):
        allow = value["action"] == "file.read" and value["resource"].get("owner_id") == value["subject"]["id"]
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


if __name__ == "__main__":
    unittest.main()
