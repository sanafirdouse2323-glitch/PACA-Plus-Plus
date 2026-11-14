from __future__ import annotations

import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from agent.paca_client import PACAClient
from agent.langgraph_integration.paca_tools import (
    ActionSpec,
    PACALangGraphError,
    SQLiteOperationLedger,
    UnresolvedOperationError,
    build_paca_langgraph_agent,
)


PERMIT_ID = "00000000-0000-0000-0000-000000000123"
EXECUTION_ID = "00000000-0000-0000-0000-000000000456"


class FakePACAHandler(BaseHTTPRequestHandler):
    requests_seen: list[dict[str, Any]] = []
    execution_statuses: list[int] = []
    next_execution_status = 200

    def _respond(self, status: int, body: dict[str, Any]) -> None:
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).requests_seen.append({
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "idempotency_key": self.headers.get("Idempotency-Key"),
            "body": body,
        })
        if self.path == "/v1/authorizations":
            if body["resource_id"] == "denied-resource":
                self._respond(403, {"detail": "policy_denied"})
            else:
                self._respond(201, {"permit_id": PERMIT_ID})
            return
        if self.path == "/v1/executions":
            type(self).execution_statuses.append(type(self).next_execution_status)
            status = type(self).next_execution_status
            type(self).next_execution_status = 200
            if status != 200:
                self._respond(status, {"detail": "test_upstream_or_gateway_failure"})
            else:
                self._respond(200, {
                    "execution_id": EXECUTION_ID,
                    "status": "succeeded",
                    "result": {"resource_id": body["resource_id"], "content": "protected data"},
                })
            return
        self._respond(404, {"detail": "not_found"})

    def log_message(self, *_args: Any) -> None:
        pass


class LocalPACAService:
    def __init__(self) -> None:
        FakePACAHandler.requests_seen = []
        FakePACAHandler.execution_statuses = []
        FakePACAHandler.next_execution_status = 200
        self.server = HTTPServer(("127.0.0.1", 0), FakePACAHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = PACAClient(
            f"http://127.0.0.1:{self.server.server_port}", "test-access-token"
        )

    @property
    def requests(self) -> list[dict[str, Any]]:
        return FakePACAHandler.requests_seen

    def close(self) -> None:
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()


class ScriptedToolModel:
    """Minimal deterministic chat-model double that LangGraph can invoke."""

    def __init__(self, tool_name: str, call_id: str, resource_id: str = "report-123") -> None:
        self.tool_name = tool_name
        self.call_id = call_id
        self.resource_id = resource_id
        self.bound_tool_names: list[str] = []
        self.calls = 0

    def bind_tools(self, tools: list[Any]) -> "ScriptedToolModel":
        self.bound_tool_names = [item.name for item in tools]
        return self

    def invoke(self, messages: list[Any]) -> AIMessage:
        self.calls += 1
        if self.calls == 1:
            return AIMessage(
                content="",
                tool_calls=[{
                    "name": self.tool_name,
                    "args": {
                        "resource_id": self.resource_id,
                        "arguments": {"format": "text"},
                    },
                    "id": self.call_id,
                    "type": "tool_call",
                }],
            )
        return AIMessage(content="I have processed the guarded tool result.")


def _build(
    paca: LocalPACAService,
    ledger_path: Path,
    model: ScriptedToolModel,
):
    ledger = SQLiteOperationLedger(ledger_path)
    graph = build_paca_langgraph_agent(
        model=model,
        client=paca.client,
        ledger=ledger,
        actions=[
            ActionSpec(
                tool_name="read_document",
                action="file.read",
                description="Read a document using the PACA++ protected execution gateway.",
            )
        ],
    )
    return graph, ledger


def test_real_langgraph_tool_call_is_authorized_and_executed_via_paca(tmp_path: Path) -> None:
    paca = LocalPACAService()
    ledger_path = tmp_path / "operations.sqlite3"
    model = ScriptedToolModel("read_document", "call-success")
    try:
        graph, ledger = _build(paca, ledger_path, model)
        result = graph.invoke(
            {"messages": [HumanMessage(content="Read report-123.")]},
            config={"configurable": {"thread_id": "thread-success"}},
        )
        assert model.bound_tool_names == ["read_document"]
        assert result["messages"][-1].content == "I have processed the guarded tool result."
        assert [item["path"] for item in paca.requests] == [
            "/v1/authorizations", "/v1/executions"
        ]
        authorization, execution = paca.requests
        assert authorization["body"]["action"] == "file.read"
        assert execution["body"]["action"] == "file.read"
        assert execution["body"]["permit_id"] == PERMIT_ID
        assert execution["idempotency_key"].startswith("lg-")
        assert execution["idempotency_key"] == ledger.begin(
            thread_id="thread-success",
            tool_call_id="call-success",
            action="file.read",
            resource_id="report-123",
            arguments={"format": "text"},
        ).idempotency_key
        assert len(execution["idempotency_key"]) <= 128
        ledger.close()
    finally:
        paca.close()


def test_authorization_denial_stops_before_protected_execution(tmp_path: Path) -> None:
    paca = LocalPACAService()
    try:
        graph, ledger = _build(
            paca, tmp_path / "denied.sqlite3",
            ScriptedToolModel("read_document", "call-denied", "denied-resource"),
        )
        with pytest.raises(PACALangGraphError, match="denied protected action"):
            graph.invoke(
                {"messages": [HumanMessage(content="Read denied-resource.")]},
                config={"configurable": {"thread_id": "thread-denied"}},
            )
        assert [item["path"] for item in paca.requests] == ["/v1/authorizations"]
        ledger.close()
    finally:
        paca.close()


def test_unknown_execution_replay_reuses_same_permit_and_idempotency_key(tmp_path: Path) -> None:
    paca = LocalPACAService()
    FakePACAHandler.next_execution_status = 503
    model = ScriptedToolModel("read_document", "call-replay")
    ledger_path = tmp_path / "replay.sqlite3"
    try:
        graph, ledger = _build(paca, ledger_path, model)
        config = {"configurable": {"thread_id": "thread-replay"}}
        with pytest.raises(PACALangGraphError, match="outcome is unknown"):
            graph.invoke(
                {"messages": [HumanMessage(content="Read report-123.")]},
                config=config,
            )
        # Rebuild with the same stable tool-call identity, as a host replay would.
        retry_model = ScriptedToolModel("read_document", "call-replay")
        retry_graph = build_paca_langgraph_agent(
            model=retry_model,
            client=paca.client,
            ledger=ledger,
            actions=[
                ActionSpec(
                    tool_name="read_document",
                    action="file.read",
                    description="Read a document using the PACA++ protected execution gateway.",
                )
            ],
        )
        result = retry_graph.invoke(
            {"messages": [HumanMessage(content="Read report-123.")]},
            config=config,
        )
        assert result["messages"][-1].content == "I have processed the guarded tool result."
        authorizations = [item for item in paca.requests if item["path"] == "/v1/authorizations"]
        executions = [item for item in paca.requests if item["path"] == "/v1/executions"]
        assert len(authorizations) == 1
        assert len(executions) == 2
        assert executions[0]["body"]["permit_id"] == executions[1]["body"]["permit_id"] == PERMIT_ID
        assert executions[0]["idempotency_key"] == executions[1]["idempotency_key"]
        ledger.close()
    finally:
        paca.close()


def test_new_tool_call_cannot_duplicate_unresolved_action_in_same_thread(tmp_path: Path) -> None:
    paca = LocalPACAService()
    FakePACAHandler.next_execution_status = 503
    ledger_path = tmp_path / "duplicate.sqlite3"
    try:
        graph, ledger = _build(
            paca, ledger_path, ScriptedToolModel("read_document", "call-original")
        )
        config = {"configurable": {"thread_id": "thread-duplicate"}}
        with pytest.raises(PACALangGraphError, match="outcome is unknown"):
            graph.invoke(
                {"messages": [HumanMessage(content="Read report-123.")]},
                config=config,
            )
        before = len(paca.requests)
        duplicate_graph = build_paca_langgraph_agent(
            model=ScriptedToolModel("read_document", "call-new"),
            client=paca.client,
            ledger=ledger,
            actions=[
                ActionSpec(
                    tool_name="read_document",
                    action="file.read",
                    description="Read a document using the PACA++ protected execution gateway.",
                )
            ],
        )
        with pytest.raises(UnresolvedOperationError, match="reconcile it"):
            duplicate_graph.invoke(
                {"messages": [HumanMessage(content="Read report-123 again.")]},
                config=config,
            )
        assert len(paca.requests) == before
        ledger.close()
    finally:
        paca.close()


def test_model_cannot_invoke_undeclared_direct_effect_tool(tmp_path: Path) -> None:
    paca = LocalPACAService()
    model = ScriptedToolModel("direct_database_write", "call-bypass")
    try:
        graph, ledger = _build(paca, tmp_path / "bypass.sqlite3", model)
        assert model.bound_tool_names == ["read_document"]
        with pytest.raises(Exception):
            graph.invoke(
                {"messages": [HumanMessage(content="Write directly to the database.")]},
                config={"configurable": {"thread_id": "thread-bypass"}},
            )
        assert paca.requests == []
        ledger.close()
    finally:
        paca.close()


def test_host_resource_allowlist_is_checked_before_authorization(tmp_path: Path) -> None:
    paca = LocalPACAService()
    ledger = SQLiteOperationLedger(tmp_path / "allowlist.sqlite3")
    try:
        graph = build_paca_langgraph_agent(
            model=ScriptedToolModel("read_document", "call-outside-allowlist", "other-doc"),
            client=paca.client,
            ledger=ledger,
            actions=[
                ActionSpec(
                    tool_name="read_document",
                    action="file.read",
                    description="Read one pre-approved document.",
                    allowed_resource_ids=("report-123",),
                )
            ],
        )
        with pytest.raises(PACALangGraphError, match="not_in_host_allowlist"):
            graph.invoke(
                {"messages": [HumanMessage(content="Read other-doc.")]},
                config={"configurable": {"thread_id": "thread-allowlist"}},
            )
        assert paca.requests == []
        ledger.close()
    finally:
        paca.close()
