from __future__ import annotations

from uuid import UUID

import pytest
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.store.memory import InMemoryStore
from pydantic import Field, ValidationError

from agent.langgraph_adapter import (
    PACAArgsModel,
    PACAExecutionOutcomeUnknown,
    PACAFrameworkError,
    PACAOperation,
    build_paca_langgraph_agent,
)
from agent.paca_client import PACARequestError


PERMIT_ID = "00000000-0000-0000-0000-000000000123"


class ReadDocumentArgs(PACAArgsModel):
    resource_id: str = Field(min_length=1, max_length=256)
    format: str = Field(default="text", pattern="^(text|json)$")


class FakePACAClient:
    def __init__(self, execute_results=None):
        self.authorizations = []
        self.executions = []
        self.execute_results = list(execute_results or [{"execution_id": "00000000-0000-0000-0000-000000000456",
                                                        "status": "succeeded", "result": {"content": "safe"}}])

    def authorize(self, *, action, resource_id, arguments):
        self.authorizations.append((action, resource_id, dict(arguments)))
        return {"permit_id": PERMIT_ID, "status": "issued"}

    def execute(self, *, action, resource_id, arguments, permit_id, idempotency_key):
        self.executions.append((action, resource_id, dict(arguments), permit_id, idempotency_key))
        result = self.execute_results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class FakeModel:
    def __init__(self, turns):
        self.turns = list(turns)
        self.bound_tools = None
        self.messages_seen = []

    def bind_tools(self, tools):
        self.bound_tools = list(tools)
        return self

    def invoke(self, messages, config=None):
        self.messages_seen.append(list(messages))
        if not self.turns:
            raise AssertionError("unexpected model invocation")
        return self.turns.pop(0)


def operation():
    return PACAOperation(
        name="read_document",
        description="Read an authorized document through the PACA++ gateway.",
        action="file.read",
        resource_id_field="resource_id",
        args_schema=ReadDocumentArgs,
    )


def build_graph(model, client, *, checkpointer=None, store=None):
    return build_paca_langgraph_agent(
        model=model,
        paca_client=client,
        operations=[operation()],
        checkpointer=checkpointer or InMemorySaver(),
        store=store or InMemoryStore(),
    )


def tool_call(name="read_document", args=None, call_id="call-001"):
    return AIMessage(
        content="",
        tool_calls=[
            {
                "name": name,
                "args": args if args is not None else {"resource_id": "report-1", "format": "text"},
                "id": call_id,
                "type": "tool_call",
            }
        ],
    )


def test_real_langgraph_tool_execution_routes_only_through_paca_gateway():
    client = FakePACAClient()
    model = FakeModel([tool_call(), AIMessage(content="The approved document was read.")])
    graph = build_graph(model, client)
    config = {"configurable": {"thread_id": "integration-test-thread"}}

    result = graph.invoke({"messages": [HumanMessage(content="Read report-1.")]}, config)

    assert result["messages"][-1].content == "The approved document was read."
    assert len(model.bound_tools) == 1
    assert model.bound_tools[0].name == "read_document"
    assert set(model.bound_tools[0].tool_call_schema.model_fields) == {"resource_id", "format"}
    assert "runtime" not in model.bound_tools[0].tool_call_schema.model_fields
    assert client.authorizations == [("file.read", "report-1", {"format": "text"})]
    assert len(client.executions) == 1
    action, resource_id, arguments, permit_id, idempotency_key = client.executions[0]
    assert (action, resource_id, arguments, permit_id) == (
        "file.read", "report-1", {"format": "text"}, PERMIT_ID
    )
    UUID(permit_id)
    assert idempotency_key.startswith("lg-")
    assert len(idempotency_key) == 67


def test_unregistered_model_tool_call_is_rejected_before_any_gateway_request():
    client = FakePACAClient()
    model = FakeModel([tool_call(name="direct_database_delete", args={"table": "records"})])
    graph = build_graph(model, client)
    config = {"configurable": {"thread_id": "unregistered-tool-thread"}}

    with pytest.raises(PACAFrameworkError, match="unregistered_tool_call_forbidden"):
        graph.invoke({"messages": [HumanMessage(content="Delete a record.")]}, config)

    assert client.authorizations == []
    assert client.executions == []


def test_model_cannot_override_the_host_configured_paca_action():
    client = FakePACAClient()
    model = FakeModel([
        tool_call(args={"resource_id": "report-1", "format": "text", "action": "admin.delete"})
    ])
    graph = build_graph(model, client)
    config = {"configurable": {"thread_id": "extra-argument-thread"}}

    with pytest.raises(ValidationError):
        graph.invoke({"messages": [HumanMessage(content="Read a report.")]}, config)

    assert client.authorizations == []
    assert client.executions == []


def test_tool_call_id_and_thread_id_produce_stable_idempotency_key_on_resume():
    client = FakePACAClient([
        PACARequestError(None, "transport_outcome_unknown; reconcile before retry"),
        {"execution_id": "00000000-0000-0000-0000-000000000456",
         "status": "succeeded", "result": {"content": "safe"}, "idempotent_replay": True},
    ])
    model = FakeModel([tool_call(), AIMessage(content="Recovered safely.")])
    checkpointer = InMemorySaver()
    store = InMemoryStore()
    graph = build_graph(model, client, checkpointer=checkpointer, store=store)
    config = {"configurable": {"thread_id": "resume-after-network-error"}}

    with pytest.raises(PACARequestError):
        graph.invoke({"messages": [HumanMessage(content="Read report-1.")]}, config)

    # LangGraph resumes the failed ToolNode from its last checkpoint. The journal
    # must reuse the pre-effect permit and idempotency key instead of authorizing again.
    result = graph.invoke(None, config)

    assert result["messages"][-1].content == "Recovered safely."
    assert len(client.authorizations) == 1
    assert len(client.executions) == 2
    first, second = client.executions
    assert first[3] == second[3] == PERMIT_ID
    assert first[4] == second[4]
    assert first[4].startswith("lg-")
    assert len(model.turns) == 0


def test_gateway_unknown_outcome_is_not_converted_to_model_retry_instruction():
    client = FakePACAClient([
        {"execution_id": "00000000-0000-0000-0000-000000000456", "status": "unknown",
         "retry_safe": False}
    ])
    model = FakeModel([tool_call()])
    graph = build_graph(model, client)
    config = {"configurable": {"thread_id": "unknown-outcome-thread"}}

    with pytest.raises(PACAExecutionOutcomeUnknown) as error:
        graph.invoke({"messages": [HumanMessage(content="Read report-1.")]}, config)

    assert error.value.execution_id == "00000000-0000-0000-0000-000000000456"
    assert error.value.retry_safe is False
    assert len(client.authorizations) == 1
    assert len(client.executions) == 1
    # The failing ToolNode is not returned to the model as ordinary text.
    assert len(model.turns) == 0


def test_journal_rejects_a_replayed_tool_call_with_changed_arguments():
    client = FakePACAClient()
    model = FakeModel([tool_call(), AIMessage(content="done")])
    store = InMemoryStore()
    graph = build_graph(model, client, store=store)
    config = {"configurable": {"thread_id": "journal-conflict-thread"}}

    result = graph.invoke({"messages": [HumanMessage(content="Read report-1.")]}, config)
    assert result["messages"][-1].content == "done"

    # A second graph/model proposing the same call ID with changed args is not a
    # new action: the persistent journal rejects the mismatch before gateway I/O.
    changed_model = FakeModel([tool_call(args={"resource_id": "report-2", "format": "text"})])
    changed_graph = build_graph(changed_model, client, store=store)
    with pytest.raises(PACAFrameworkError, match="paca_execution_journal_conflict"):
        changed_graph.invoke(
            {"messages": [HumanMessage(content="Different operation.")]}, config
        )
    assert len(client.authorizations) == 1
    assert len(client.executions) == 1
