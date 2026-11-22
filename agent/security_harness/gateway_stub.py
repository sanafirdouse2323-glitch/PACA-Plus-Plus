from __future__ import annotations

import json
import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PERMIT_ID = "00000000-0000-0000-0000-000000000123"
EXECUTION_ID = "00000000-0000-0000-0000-000000000456"


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"detail": "not_found"})

    def do_POST(self) -> None:
        if self.headers.get("Authorization") != "Bearer harness-only-agent-token":
            self._send(401, {"detail": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 65536:
                raise ValueError("invalid_request_size")
            payload = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            self._send(400, {"detail": "invalid_json"})
            return

        if self.path == "/v1/authorizations":
            if payload.get("action") != "file.read":
                self._send(403, {"detail": "action_not_allowed"})
                return
            self._send(201, {"permit_id": PERMIT_ID, "status": "issued"})
            return

        if self.path == "/v1/executions":
            if (
                payload.get("permit_id") != PERMIT_ID
                or payload.get("action") != "file.read"
                or not self.headers.get("Idempotency-Key")
            ):
                self._send(403, {"detail": "execution_contract_rejected"})
                return
            self._send(
                200,
                {
                    "execution_id": EXECUTION_ID,
                    "status": "succeeded",
                    "result": {"content": "PACA-protected test result"},
                },
            )
            return

        self._send(404, {"detail": "not_found"})

    def log_message(self, *_args) -> None:
        pass


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        os.environ["PACA_TLS_CERT_FILE"],
        os.environ["PACA_TLS_KEY_FILE"],
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
