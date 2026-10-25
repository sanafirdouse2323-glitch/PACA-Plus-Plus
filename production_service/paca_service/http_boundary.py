"""Reject ambiguous HTTP headers and bound request-body consumption at the ASGI boundary."""
from __future__ import annotations

from collections import Counter

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MAX_REQUEST_BYTES = 1_048_576
_CRITICAL_HEADERS = frozenset({
    b"authorization",
    b"idempotency-key",
    b"content-length",
    b"transfer-encoding",
    b"host",
    b"content-type",
})


class _RequestBodyTooLarge(Exception):
    pass


class RequestBoundaryMiddleware:
    """Reject duplicate security/framing headers and cap bytes read from each request.

    The check runs before FastAPI's authentication and body parsing so different
    layers cannot select different Authorization/Idempotency-Key values. The
    receive wrapper also covers chunked requests without Content-Length.
    """

    def __init__(self, app: ASGIApp, max_body_bytes: int = MAX_REQUEST_BYTES) -> None:
        if type(max_body_bytes) is not int or max_body_bytes < 1:
            raise ValueError("max_body_bytes must be a positive integer")
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        counts = Counter(
            name.lower() for name, _ in scope.get("headers", [])
            if name.lower() in _CRITICAL_HEADERS
        )
        if any(count > 1 for count in counts.values()):
            await JSONResponse(
                status_code=400,
                content={"detail": {"code": "ambiguous_duplicate_header"}},
            )(scope, receive, send)
            return

        headers = {
            name.lower(): value for name, value in scope.get("headers", [])
            if name.lower() in _CRITICAL_HEADERS
        }
        raw_length = headers.get(b"content-length")
        has_transfer_encoding = b"transfer-encoding" in headers
        if raw_length is not None and has_transfer_encoding:
            await JSONResponse(
                status_code=400,
                content={"detail": {"code": "ambiguous_request_framing"}},
            )(scope, receive, send)
            return

        expected_length: int | None = None
        if raw_length is not None:
            try:
                length_text = raw_length.decode("ascii")
                if not length_text or not length_text.isdecimal():
                    raise ValueError
                expected_length = int(length_text)
            except (UnicodeDecodeError, ValueError):
                await JSONResponse(
                    status_code=400,
                    content={"detail": {"code": "invalid_content_length"}},
                )(scope, receive, send)
                return
            if expected_length > self.max_body_bytes:
                await JSONResponse(
                    status_code=413,
                    content={"detail": {"code": "request_body_too_large"}},
                )(scope, receive, send)
                return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    raise _RequestBodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _RequestBodyTooLarge:
            # FastAPI parses JSON bodies before calling route handlers, so no
            # response should have started. Avoid attempting a second response
            # if a future streaming endpoint changes that assumption.
            if not response_started:
                await JSONResponse(
                    status_code=413,
                    content={"detail": {"code": "request_body_too_large"}},
                )(scope, receive, send)
