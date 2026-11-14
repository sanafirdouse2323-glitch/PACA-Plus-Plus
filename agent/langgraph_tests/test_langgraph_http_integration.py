from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from langchain_core.messages import AIMessage, HumanMessage
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.store.memory import InMemoryStore
from pydantic import Field

from agent.langgraph_adapter import (
    PACAArgsModel,
    PACAOperation,
    build_paca_langgraph_agent,
)
from agent.paca_client import PACAClient

PERMIT_ID = "00000000-0000-0000-0000-000000000123"
EXECUTION_ID = "00000000-0000-0000-0000-000000000456"


class ReadArgs(PACAArgsModel):
    resource_id: str = Field(min_length=1, max_length=256)
    format: str = Field(default="text", pattern="^(text|json)$")


class DeterministicChatModel:
    """A deterministic tool-calling model double; LangGraph itself is not mocked."""

    def __init__(self):
        self.turns = [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "read_file",
                        "args": {"resource_id": "report-7", "format": "text"},
                        "id": "call-http-001",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(content="The gateway returned the approved file result."),
        ]

    def bind_tools(self, tools):
        self.tools = list(tools)
        return self

    def invoke(self, messages, config=None):
        assert self.turns, "unexpected extra model turn"
        return self.turns.pop(0)


def test_langgraph_calls_real_paca_client_authorize_and_execute_http_endpoints():
    observed = []

    class GatewayContractHandler(BaseHTTPRequestHandler):
        def _send(self, status, payload):
            encoded = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            observed.append(
                {
                    "path": self.path,
                    "authorization": self.headers.get("Authorization"),
                    "idempotency_key": self.headers.get("Idempotency-Key"),
                    "payload": payload,
                }
            )
            if self.path == "/v1/authorizations":
                self._send(201, {"permit_id": PERMIT_ID, "status": "issued"})
                return
            if self.path == "/v1/executions":
                self._send(
                    200,
                    {
                        "execution_id": EXECUTION_ID,
                        "status": "succeeded",
                        "result": {"content": "authorized file content"},
                    },
                )
                return
            self._send(404, {"detail": {"code": "not_found"}})

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), GatewayContractHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        client = PACAClient(
            f"http://127.0.0.1:{server.server_port}",
            access_token="local-test-access-token",
        )
        model = DeterministicChatModel()
        operation = PACAOperation(
            name="read_file",
            description="Read a file through the PACA++ authorization gateway.",
            action="file.read",
            resource_id_field="resource_id",
            args_schema=ReadArgs,
        )
        graph = build_paca_langgraph_agent(
            model=model,
            paca_client=client,
            operations=[operation],
            checkpointer=InMemorySaver(),
            store=InMemoryStore(),
        )
        config = {"configurable": {"thread_id": "http-contract-thread"}}
        result = graph.invoke(
            {"messages": [HumanMessage(content="Read report-7.")]},
            config,
        )
    finally:
        server.shutdown()
        thread.join()
        server.server_close()

    assert result["messages"][-1].content == "The gateway returned the approved file result."
    assert [item["path"] for item in observed] == [
        "/v1/authorizations",
        "/v1/executions",
    ]
    assert all(
        item["authorization"] == "Bearer local-test-access-token"
        for item in observed
    )
    assert observed[0]["idempotency_key"] is None
    assert observed[0]["payload"] == {
        "action": "file.read",
        "resource_id": "report-7",
        "arguments": {"format": "text"},
    }
    assert observed[1]["idempotency_key"].startswith("lg-")
    assert observed[1]["payload"] == {
        "action": "file.read",
        "resource_id": "report-7",
        "arguments": {"format": "text"},
        "permit_id": PERMIT_ID,
    }
