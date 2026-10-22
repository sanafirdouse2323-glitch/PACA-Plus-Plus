"""Minimal standard-library HTTP API for the protected operation gateway.

Run behind a TLS-terminating trusted reverse proxy in production. This server defaults
to loopback and does not parse client-supplied authorization context or tool callbacks.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from typing import Any, Callable
from urllib.parse import urlparse

from .durable import IdempotencyConflict, OperationOutcomeUnknown, OperationStateError
from .gateway import (
    AuthorizationDenied,
    ContextChanged,
    OperationOutcomeUnresolved,
    PolicyEvaluationFailed,
    ProtectedToolGateway,
)


_MAX_REQUEST_BYTES = 262_144


def make_server(
    gateway: ProtectedToolGateway,
    host: str = "127.0.0.1",
    port: int = 8080,
    *,
    max_request_bytes: int = _MAX_REQUEST_BYTES,
) -> ThreadingHTTPServer:
    if max_request_bytes < 1024 or max_request_bytes > _MAX_REQUEST_BYTES:
        raise ValueError("max_request_bytes must be between 1 KiB and 256 KiB")

    class Handler(BaseHTTPRequestHandler):
        server_version = "PACA-Gateway"
        sys_version = ""

        def setup(self) -> None:
            super().setup()
            # Bound stalled clients; deploy behind a reverse proxy with its own
            # request/header/body timeouts and rate limits as well.
            self.connection.settimeout(10.0)

        def log_message(self, format: str, *args: Any) -> None:
            # Avoid default request logging that may include sensitive URL query strings.
            return

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _error(self, status: int, code: str, operation_id: str | None = None) -> None:
            payload: dict[str, Any] = {"error": code}
            if operation_id:
                payload["operation_id"] = operation_id
            self._send(status, payload)

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            if path != "/v1/execute":
                self._error(404, "not_found")
                return
            if self.headers.get("Transfer-Encoding"):
                self._error(400, "transfer_encoding_not_supported")
                return
            if self.headers.get_content_type() != "application/json":
                self._error(415, "application_json_required")
                return
            raw_length = self.headers.get("Content-Length")
            try:
                length = int(raw_length) if raw_length is not None else -1
            except ValueError:
                length = -1
            if length < 0 or length > max_request_bytes:
                self._error(413 if length > max_request_bytes else 400, "invalid_content_length")
                return
            try:
                raw = self.rfile.read(length)
            except OSError:
                self._error(408, "request_body_timeout")
                return
            if len(raw) != length:
                self._error(400, "incomplete_request_body")
                return
            try:
                payload = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._error(400, "invalid_json")
                return
            if not isinstance(payload, dict) or set(payload) - {"action", "resource", "arguments"}:
                self._error(400, "unexpected_request_fields")
                return
            if not {"action", "resource"} <= set(payload):
                self._error(400, "action_and_resource_required")
                return
            arguments = payload.get("arguments", {})
            if not isinstance(arguments, dict):
                self._error(400, "arguments_must_be_object")
                return
            try:
                result = gateway.execute(
                    self.headers.get("Authorization"),
                    action=payload["action"],
                    resource=payload["resource"],
                    arguments=arguments,
                    idempotency_key=self.headers.get("Idempotency-Key", ""),
                )
                self._send(200, {
                    "operation_id": result.operation_id,
                    "status": result.status,
                    "result": result.result,
                    "replayed": result.replayed,
                    "policy_reason": result.policy_reason,
                })
            except PermissionError:
                self._error(401, "authentication_required")
            except AuthorizationDenied:
                self._error(403, "request_denied")
            except (IdempotencyConflict, ContextChanged):
                self._error(409, "request_conflict")
            except OperationOutcomeUnresolved as exc:
                self._error(503, "effect_outcome_unknown", exc.operation_id)
            except OperationOutcomeUnknown:
                self._error(503, "effect_outcome_unknown")
            except OperationStateError:
                self._error(409, "operation_not_executable")
            except PolicyEvaluationFailed:
                self._error(503, "authorization_service_unavailable")
            except ValueError:
                self._error(400, "invalid_request")
            except Exception:
                # Internal exceptions and downstream response bodies are never returned.
                self._error(500, "internal_error")

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            prefix = "/v1/operations/"
            if not path.startswith(prefix):
                self._error(404, "not_found")
                return
            operation_id = path[len(prefix):]
            try:
                result = gateway.get_operation_status(self.headers.get("Authorization"), operation_id)
                self._send(200, result)
            except PermissionError:
                self._error(401, "authentication_required")
            except LookupError:
                self._error(404, "operation_not_found")
            except ValueError:
                self._error(400, "invalid_operation_id")
            except Exception:
                self._error(500, "internal_error")

    return ThreadingHTTPServer((host, port), Handler)
