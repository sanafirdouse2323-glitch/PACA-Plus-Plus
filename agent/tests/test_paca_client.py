from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from agent.paca_client import PACAClient


def test_client_performs_authorize_then_execute_with_same_operation_and_key():
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            observed.append((self.path, self.headers.get("Authorization"),
                             self.headers.get("Idempotency-Key"), body))
            if self.path == "/v1/authorizations":
                result = {"permit_id": "permit-123"}
            else:
                result = {"execution_id": "exec-123", "status": "succeeded"}
            encoded = json.dumps(result).encode()
            self.send_response(201 if self.path.endswith("authorizations") else 200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = PACAClient(f"http://127.0.0.1:{server.server_port}", "test-token")
        result = client.authorize_and_execute(
            action="file.read",
            resource_id="report-1",
            arguments={"format": "text"},
            idempotency_key="stable-operation-1",
        )
    finally:
        server.shutdown()
        thread.join()
        server.server_close()

    assert result["status"] == "succeeded"
    assert [entry[0] for entry in observed] == ["/v1/authorizations", "/v1/executions"]
    assert all(entry[1] == "Bearer test-token" for entry in observed)
    assert observed[0][2] is None
    assert observed[1][2] == "stable-operation-1"
    assert observed[0][3] == {
        "action": "file.read", "resource_id": "report-1", "arguments": {"format": "text"}
    }
    assert observed[1][3] == {
        "action": "file.read", "resource_id": "report-1",
        "arguments": {"format": "text"}, "permit_id": "permit-123"
    }


def test_client_rejects_invalid_configuration_and_key():
    import pytest
    with pytest.raises(ValueError):
        PACAClient("not-a-url", "token")
    with pytest.raises(ValueError):
        PACAClient("http://localhost", "bad\ntoken")
    client = PACAClient("http://localhost", "token")
    with pytest.raises(ValueError):
        client.authorize_and_execute(
            action="file.read", resource_id="r", arguments={}, idempotency_key="bad\nkey"
        )



def test_client_does_not_follow_redirects():
    import pytest
    from agent.paca_client import PACARequestError

    observed = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            observed.append(self.path)
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/collect")
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = PACAClient(f"http://127.0.0.1:{server.server_port}", "test-token")
        with pytest.raises(PACARequestError) as error:
            client.authorize_and_execute(
                action="file.read", resource_id="report-1", arguments={},
                idempotency_key="stable-operation-2",
            )
        assert error.value.status == 302
        assert observed == ["/v1/authorizations"]
    finally:
        server.shutdown()
        thread.join()
        server.server_close()



def test_execution_retry_reuses_the_original_permit_and_idempotency_key():
    from agent.paca_client import PACARequestError
    import pytest

    observed = []
    execution_attempts = 0

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status, payload):
            encoded = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_POST(self):
            nonlocal execution_attempts
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            key = self.headers.get("Idempotency-Key")
            observed.append((self.path, key, body))
            if self.path == "/v1/authorizations":
                self._send(201, {"permit_id": "00000000-0000-0000-0000-000000000123"})
                return
            execution_attempts += 1
            if execution_attempts == 1:
                self._send(503, {"detail": {"code": "temporary_store_failure"}})
            else:
                self._send(200, {"execution_id": "00000000-0000-0000-0000-000000000456",
                                 "status": "succeeded", "idempotent_replay": True})

        def do_GET(self):
            observed.append((self.path, None, None))
            self._send(200, {"status": "succeeded"})

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = PACAClient(f"http://127.0.0.1:{server.server_port}", "test-token")
        with pytest.raises(PACARequestError) as error:
            client.authorize_and_execute(
                action="file.read", resource_id="report-1", arguments={},
                idempotency_key="retry-key-1",
            )
        permit_id = error.value.permit_id
        assert permit_id == "00000000-0000-0000-0000-000000000123"

        result = client.execute(
            action="file.read", resource_id="report-1", arguments={},
            permit_id=permit_id, idempotency_key="retry-key-1",
        )
        assert result["status"] == "succeeded"
        assert observed[1][2]["permit_id"] == observed[2][2]["permit_id"] == permit_id
        assert observed[1][1] == observed[2][1] == "retry-key-1"

        status = client.execution_status("00000000-0000-0000-0000-000000000456")
        assert status["status"] == "succeeded"
        assert observed[-1][0] == "/v1/executions/00000000-0000-0000-0000-000000000456"
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def test_client_rejects_invalid_execution_identifiers_and_idempotency_keys():
    import pytest

    client = PACAClient("http://localhost", "test-token")
    with pytest.raises(ValueError, match="invalid_permit_id"):
        client.execute(
            action="file.read", resource_id="r", arguments={},
            permit_id="not-a-uuid", idempotency_key="valid-key",
        )
    with pytest.raises(ValueError, match="invalid_idempotency_key"):
        client.execute(
            action="file.read", resource_id="r", arguments={},
            permit_id="00000000-0000-0000-0000-000000000123",
            idempotency_key="contains spaces",
        )
