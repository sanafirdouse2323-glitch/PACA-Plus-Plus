from __future__ import annotations

import asyncio
from typing import Any

from paca_service.http_boundary import RequestBoundaryMiddleware


def invoke(headers: list[tuple[bytes, bytes]], chunks: list[bytes], max_body_bytes: int = 8):
    messages: list[dict[str, Any]] = []
    received = 0

    async def app(scope, receive, send):
        nonlocal received
        while True:
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if not message.get("more_body", False):
                    break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = RequestBoundaryMiddleware(app, max_body_bytes=max_body_bytes)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": headers,
        "client": ("test", 1234),
        "server": ("test", 80),
    }
    queue = list(chunks)

    async def receive():
        if queue:
            body = queue.pop(0)
            return {
                "type": "http.request",
                "body": body,
                "more_body": bool(queue),
            }
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    asyncio.run(middleware(scope, receive, send))
    status = next(message["status"] for message in messages if message["type"] == "http.response.start")
    return status, received, messages


def test_rejects_duplicate_authorization_and_idempotency_headers():
    for name in (b"authorization", b"idempotency-key"):
        status, _, _ = invoke(
            [(name, b"one"), (name, b"two")],
            [b""],
        )
        assert status == 400


def test_rejects_conflicting_content_length_and_transfer_encoding():
    status, _, _ = invoke(
        [(b"content-length", b"0"), (b"transfer-encoding", b"chunked")],
        [b""],
    )
    assert status == 400


def test_rejects_invalid_content_length():
    status, _, _ = invoke([(b"content-length", b"not-a-number")], [b""])
    assert status == 400


def test_rejects_declared_oversize_body_before_reading_it():
    status, received, _ = invoke([(b"content-length", b"9")], [b"123456789"])
    assert status == 413
    assert received == 0


def test_rejects_oversize_chunked_body_while_reading():
    status, received, _ = invoke([(b"transfer-encoding", b"chunked")], [b"123456", b"789"])
    assert status == 413
    assert received == 6


def test_accepts_small_unambiguous_request():
    status, received, _ = invoke([(b"content-length", b"3")], [b"abc"])
    assert status == 200
    assert received == 3
