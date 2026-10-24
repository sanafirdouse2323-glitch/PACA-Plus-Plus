from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import datetime
import hashlib
import json
import os
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    jwt = None
    rsa = None

from paca_mvp.durable import PostgresOperationStore
from paca_mvp.gateway import AuthorizationDenied, HTTPJsonActionAdapter, ProtectedToolGateway
from paca_mvp.http_api import make_server
from paca_mvp.identity import CallbackContextProvider, JWTAuthenticator
from paca_mvp.opa import OPAPolicyDecisionPoint


OPA_BASE_URL = os.environ.get("PACA_OPA_BASE_URL")
DATABASE_URL = os.environ.get("PACA_TEST_RUNTIME_DATABASE_URL") or os.environ.get("PACA_TEST_DATABASE_URL")


class DownstreamHandler(BaseHTTPRequestHandler):
    calls = []

    def log_message(self, *args):
        return

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(size))
        type(self).calls.append({
            "request": request,
            "idempotency_key": self.headers.get("Idempotency-Key"),
        })
        body = json.dumps({"remote_ok": True, "resource": request["resource"]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@unittest.skipUnless(OPA_BASE_URL and DATABASE_URL and jwt is not None,
                     "Requires live OPA, PostgreSQL and production extras")
class FullStackIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()
        DownstreamHandler.calls = []
        cls.downstream = ThreadingHTTPServer(("127.0.0.1", 0), DownstreamHandler)
        cls.thread = threading.Thread(target=cls.downstream.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.downstream.shutdown()
        cls.downstream.server_close()
        cls.thread.join(timeout=3)

    def token(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        payload = {
            "iss": "https://identity.integration.example",
            "aud": "paca-integration",
            "sub": "integration-user",
            "iat": int(now.timestamp()),
            "exp": int((now + datetime.timedelta(minutes=2)).timestamp()),
        }
        return jwt.encode(payload, self.private_key, algorithm="RS256")

    def test_real_jwt_opa_postgres_and_downstream_http_work_together(self):
        authenticator = JWTAuthenticator(
            issuer="https://identity.integration.example",
            audience="paca-integration",
            algorithms=("RS256",),
            key_resolver=lambda _token: self.public_key,
        )
        context_provider = CallbackContextProvider(
            subject_lookup=lambda _principal: {
                "status": "active", "role": "analyst", "tenant_id": "tenant-a", "user_id": "db-integration-user"
            },
            resource_lookup=lambda _principal, _action, resource, _args: {
                "owner_id": "db-integration-user" if resource == "file:r1" else "db-another-user",
                "tenant_id": "tenant-a",
                "canonical_path": "report-1" if resource == "file:r1" else "other-user-report",
            },
        )
        opa = OPAPolicyDecisionPoint(base_url=OPA_BASE_URL, required_policy_version="paca-baseline-v1")
        store = PostgresOperationStore(DATABASE_URL, initialize_schema=False)
        gateway = ProtectedToolGateway(
            authenticator=authenticator,
            context_provider=context_provider,
            policy_decision_point=opa,
            operation_store=store,
        )
        adapter = HTTPJsonActionAdapter(
            f"http://127.0.0.1:{self.downstream.server_address[1]}/execute",
            allow_insecure_loopback_for_tests=True,
        )
        gateway.register_action("file.read", adapter)
        authorization = "Bearer " + self.token()
        key = "e2e-" + uuid.uuid4().hex
        request = {
            "action": "file.read",
            "resource": "file:r1",
            "arguments": {"path": "report-1"},
        }

        first = gateway.execute(authorization, **request, idempotency_key=key)
        replay = gateway.execute(authorization, **request, idempotency_key=key)
        self.assertEqual(first.status, "succeeded")
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(first.result, {"remote_ok": True, "resource": "file:r1"})
        self.assertEqual(len(DownstreamHandler.calls), 1)
        expected_downstream_key = hashlib.sha256(json.dumps(
            {"issuer": "https://identity.integration.example",
             "subject": "integration-user", "client_idempotency_key": key},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        self.assertEqual(DownstreamHandler.calls[0]["idempotency_key"], expected_downstream_key)

        with self.assertRaises(AuthorizationDenied):
            gateway.execute(
                authorization,
                action="file.read",
                resource="file:r2",
                arguments={"path": "other-user-report"},
                idempotency_key="e2e-" + uuid.uuid4().hex,
            )
        with self.assertRaises(AuthorizationDenied):
            gateway.execute(
                authorization,
                action="file.read",
                resource="file:r1",
                arguments={"path": "../private/secret.csv"},
                idempotency_key="e2e-" + uuid.uuid4().hex,
            )
        self.assertEqual(len(DownstreamHandler.calls), 1)
        self.assertTrue(store.verify_audit_chain())


    def setUp(self):
        DownstreamHandler.calls = []

    def test_public_http_api_uses_real_jwt_opa_postgres_and_downstream_adapter(self):
        authenticator = JWTAuthenticator(
            issuer="https://identity.integration.example",
            audience="paca-integration",
            algorithms=("RS256",),
            key_resolver=lambda _token: self.public_key,
        )
        context_provider = CallbackContextProvider(
            subject_lookup=lambda _principal: {
                "status": "active", "role": "analyst", "tenant_id": "tenant-a", "user_id": "db-integration-user"
            },
            resource_lookup=lambda _principal, _action, resource, _args: {
                "owner_id": "db-integration-user" if resource == "file:r1" else "db-another-user",
                "tenant_id": "tenant-a",
                "canonical_path": "report-1" if resource == "file:r1" else "other-user-report",
            },
        )
        gateway = ProtectedToolGateway(
            authenticator=authenticator,
            context_provider=context_provider,
            policy_decision_point=OPAPolicyDecisionPoint(base_url=OPA_BASE_URL),
            operation_store=PostgresOperationStore(DATABASE_URL, initialize_schema=False),
        )
        gateway.register_action("file.read", HTTPJsonActionAdapter(
            f"http://127.0.0.1:{self.downstream.server_address[1]}/execute",
            allow_insecure_loopback_for_tests=True,
        ))
        api = make_server(gateway, host="127.0.0.1", port=0)
        api_thread = threading.Thread(target=api.serve_forever, daemon=True)
        api_thread.start()
        try:
            api_url = f"http://127.0.0.1:{api.server_address[1]}"
            authorization = "Bearer " + self.token()
            key = "http-e2e-" + uuid.uuid4().hex
            body = json.dumps({
                "action": "file.read", "resource": "file:r1",
                "arguments": {"path": "report-1"},
            }).encode()
            request = urllib.request.Request(
                api_url + "/v1/execute",
                data=body,
                headers={"Authorization": authorization, "Content-Type": "application/json",
                         "Idempotency-Key": key},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                result = json.loads(response.read())
            self.assertEqual(result["status"], "succeeded")
            self.assertEqual(result["result"], {"remote_ok": True, "resource": "file:r1"})
            self.assertEqual(len(DownstreamHandler.calls), 1)

            bad_request = urllib.request.Request(
                api_url + "/v1/execute",
                data=json.dumps({
                    "action": "file.read", "resource": "file:r1",
                    "arguments": {"path": "../private/secret.csv"},
                }).encode(),
                headers={"Authorization": authorization, "Content-Type": "application/json",
                         "Idempotency-Key": "http-e2e-" + uuid.uuid4().hex},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(bad_request, timeout=5)
            self.assertEqual(caught.exception.code, 403)
            self.assertEqual(len(DownstreamHandler.calls), 1)

            status_request = urllib.request.Request(
                api_url + "/v1/operations/" + result["operation_id"],
                headers={"Authorization": authorization},
            )
            with urllib.request.urlopen(status_request, timeout=5) as response:
                status = json.loads(response.read())
            self.assertEqual(status["status"], "succeeded")
            self.assertNotIn("result", status)
        finally:
            api.shutdown()
            api.server_close()
            api_thread.join(timeout=3)



if __name__ == "__main__":
    unittest.main()
