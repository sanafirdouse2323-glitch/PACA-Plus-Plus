from __future__ import annotations

import tempfile
from pathlib import Path

import httpx
import pytest

from paca_service.adapters import (
    EffectOutcomeUnknown,
    EffectRejected,
    EffectRequest,
    HttpAPIAdapter,
    SandboxedFileAdapter,
    ToolRegistryAdapter,
)
from paca_service.auth import Principal


def request(
    action: str,
    resource_id: str,
    arguments: dict,
    context: dict,
    execution_id: str = "00000000-0000-0000-0000-000000000001",
) -> EffectRequest:
    principal = Principal(
        subject="alice", tenant_id="tenant-1", roles=(),
        scopes=("file:read", "file:create", "tool:invoke"), tools=("text.word_count",),
    )
    return EffectRequest(execution_id, principal, action, resource_id, arguments, context)


def file_context(relative_path: str) -> dict:
    return {
        "resource": {
            "kind": "file",
            "attributes": {"relative_path": relative_path},
        }
    }


def test_sandboxed_file_read_and_create_are_real_operations_below_root():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "report.txt").write_text("alpha beta", encoding="utf-8")
        adapter = SandboxedFileAdapter(temporary)
        read = adapter.execute(
            request("file.read", "report-1", {}, file_context("report.txt"))
        )
        assert read["content"] == "alpha beta"
        assert read["bytes_read"] == 10

        created = adapter.execute(
            request("file.create", "new-1", {"content": "new report"}, file_context("new.txt"))
        )
        assert created["created"] is True
        assert (root / "new.txt").read_text(encoding="utf-8") == "new report"


def test_sandboxed_file_adapter_rejects_traversal_and_symlinks():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        outside = root.parent / (root.name + "-outside.txt")
        outside.write_text("secret", encoding="utf-8")
        try:
            (root / "link.txt").symlink_to(outside)
            adapter = SandboxedFileAdapter(temporary)
            with pytest.raises(EffectRejected, match="unsafe_resource_path"):
                adapter.execute(
                    request("file.read", "traversal", {}, file_context("../" + outside.name))
                )
            with pytest.raises(EffectRejected):
                adapter.execute(request("file.read", "symlink", {}, file_context("link.txt")))
        finally:
            outside.unlink(missing_ok=True)


def test_sandboxed_file_create_does_not_overwrite_existing_files():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "existing.txt").write_text("keep", encoding="utf-8")
        adapter = SandboxedFileAdapter(temporary)
        with pytest.raises(EffectRejected, match="file_already_exists"):
            adapter.execute(
                request(
                    "file.create", "existing", {"content": "overwrite"},
                    file_context("existing.txt"),
                )
            )
        assert (root / "existing.txt").read_text(encoding="utf-8") == "keep"


def test_tool_registry_only_dispatches_registered_tool_names():
    tools = ToolRegistryAdapter()
    tools.register("text.word_count", lambda data, req: {"words": len(data["text"].split())})
    ctx = {"resource": {"kind": "tool"}}
    assert tools.supports("tool.invoke", {"name": "text.word_count"}, ctx)
    assert not tools.supports("tool.invoke", {"name": "shell.run"}, ctx)
    result = tools.execute(
        request(
            "tool.invoke", "tool-resource",
            {"name": "text.word_count", "input": {"text": "one two three"}},
            ctx,
        )
    )
    assert result == {"words": 3}


def test_http_adapter_uses_configured_host_and_stable_downstream_idempotency_key():
    observed = []

    def responder(req: httpx.Request) -> httpx.Response:
        observed.append(req)
        return httpx.Response(200, json={"document_id": "doc-1"})

    client = httpx.Client(transport=httpx.MockTransport(responder))
    adapter = HttpAPIAdapter(
        "https://internal.example",
        {"document.read": {"method": "GET", "path": "/v1/documents/{resource_id}", "args_mode": "query"}},
        timeout_seconds=1,
        bearer_token="service-secret",
        client=client,
    )
    result = adapter.execute(
        request(
            "document.read", "doc/1", {"view": "summary"},
            {"resource": {"kind": "document"}},
        )
    )
    outgoing = observed[0]
    assert outgoing.url.host == "internal.example"
    assert outgoing.url.raw_path == b"/v1/documents/doc%2F1?view=summary"
    assert outgoing.headers["Idempotency-Key"] == "00000000-0000-0000-0000-000000000001"
    assert outgoing.headers["Authorization"] == "Bearer service-secret"
    assert outgoing.url.params["view"] == "summary"
    assert result["body"]["document_id"] == "doc-1"
    adapter.close()


def test_http_adapter_never_follows_redirects_and_classifies_uncertain_effects():
    redirect_client = httpx.Client(
        transport=httpx.MockTransport(lambda req: httpx.Response(302, headers={"Location": "https://evil.example"}))
    )
    adapter = HttpAPIAdapter(
        "https://internal.example",
        {"document.update": {"method": "PATCH", "path": "/v1/documents/{resource_id}", "args_mode": "json"}},
        timeout_seconds=1,
        client=redirect_client,
    )
    with pytest.raises(EffectOutcomeUnknown, match="upstream_non_success_response"):
        adapter.execute(
            request("document.update", "doc-1", {"name": "x"}, {"resource": {"kind": "document"}})
        )
    adapter.close()

    def broken(req: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "server"})
    adapter = HttpAPIAdapter(
        "https://internal.example",
        {"document.update": {"method": "PATCH", "path": "/v1/documents/{resource_id}", "args_mode": "json"}},
        timeout_seconds=1,
        client=httpx.Client(transport=httpx.MockTransport(broken)),
    )
    with pytest.raises(EffectOutcomeUnknown, match="upstream_server_outcome_unknown"):
        adapter.execute(
            request("document.update", "doc-1", {"name": "x"}, {"resource": {"kind": "document"}})
        )
    adapter.close()


def test_http_adapter_rejects_unsafe_route_configuration():
    with pytest.raises(ValueError):
        HttpAPIAdapter(
            "https://internal.example",
            {"document.read": {"method": "GET", "path": "//attacker.example/{resource_id}", "args_mode": "query"}},
            timeout_seconds=1,
        )
    with pytest.raises(ValueError):
        HttpAPIAdapter(
            "https://internal.example",
            {"document.update": {"method": "PATCH", "path": "/v1/documents/{resource_id}", "args_mode": "query"}},
            timeout_seconds=1,
        )


def test_http_adapter_stops_reading_when_upstream_response_exceeds_size_limit():
    class TrackingStream(httpx.SyncByteStream):
        def __init__(self):
            self.chunks_yielded = 0

        def __iter__(self):
            for _ in range(100):
                self.chunks_yielded += 1
                yield b"x" * 8

    stream = TrackingStream()
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(
                200,
                headers={"content-type": "application/json"},
                stream=stream,
            )
        )
    )
    adapter = HttpAPIAdapter(
        "https://internal.example",
        {"document.read": {"method": "GET", "path": "/v1/documents/{resource_id}", "args_mode": "query"}},
        timeout_seconds=1,
        client=client,
        max_response_bytes=16,
    )
    result = adapter.execute(
        request("document.read", "doc-1", {}, {"resource": {"kind": "document"}})
    )
    assert result == {"status_code": 200, "response_body_omitted": "size_limit"}
    assert stream.chunks_yielded < 100
    adapter.close()
