from __future__ import annotations

import os
from uuid import uuid4

import pytest
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.store.postgres import PostgresStore
from pydantic import Field

from agent.langgraph_adapter import (
    PACAArgsModel,
    PACAOperation,
    build_paca_langgraph_agent,
)
from agent.operation_ledger import (
    OperationInProgress,
    PostgresOperationLedger,
)
from agent.paca_client import PACARequestError

DATABASE_URL = os.environ.get("PACA_AGENT_TEST_DATABASE_URL")


class ReadArgs(PACAArgsModel):
    resource_id: str = Field(min_length=1, max_length=256)
    format: str = Field(default="text", pattern="^(text|json)$")


class FakeModel:
    def __init__(self, turns):
        self.turns = list(turns)

    def bind_tools(self, tools):
        self.tools = list(tools)
        return self

    def invoke(self, messages, config=None):
        if not self.turns:
            raise AssertionError("unexpected model invocation")
        return self.turns.pop(0)


def operation() -> PACAOperation:
    return PACAOperation(
        name="read_document",
        description="Read an authorized document through PACA++.",
        action="file.read",
        resource_id_field="resource_id",
        args_schema=ReadArgs,
    )


def tool_call(call_id: str) -> AIMessage:
    return AIMessage(
        content="",
        tool_calls=[
            {
                "name": "read_document",
                "args": {"resource_id": "report-persistent", "format": "text"},
                "id": call_id,
                "type": "tool_call",
            }
        ],
    )


@pytest.fixture
def postgres_ledgers():
    if not DATABASE_URL:
        pytest.skip("PACA_AGENT_TEST_DATABASE_URL is not configured")
    first = PostgresOperationLedger(DATABASE_URL, claim_ttl_seconds=60)
    second = PostgresOperationLedger(DATABASE_URL, claim_ttl_seconds=60)
    first.open()
    second.open()
    first.ping()
    yield first, second
    first.close()
    second.close()


def test_postgres_ledger_deduplicates_authorization_and_serializes_workers(postgres_ledgers):
    first, second = postgres_ledgers
    thread_id = f"parallel-{uuid4()}"
    call_id = f"call-{uuid4()}"
    fingerprint = "a" * 64
    idem = "lg-" + "b" * 64

    first_record = first.save_authorization(
        thread_id=thread_id,
        tool_call_id=call_id,
        tool_name="read_document",
        action="file.read",
        request_fingerprint=fingerprint,
        permit_id="00000000-0000-0000-0000-000000000123",
        idempotency_key=idem,
    )
    # Simulate a second worker whose authorize request raced and returned a
    # different permit. The unique transaction key makes it reuse the winner.
    second_record = second.save_authorization(
        thread_id=thread_id,
        tool_call_id=call_id,
        tool_name="read_document",
        action="file.read",
        request_fingerprint=fingerprint,
        permit_id="00000000-0000-0000-0000-000000000999",
        idempotency_key=idem,
    )
    assert second_record.permit_id == first_record.permit_id

    claim = first.claim_execution(
        thread_id=thread_id,
        tool_call_id=call_id,
        tool_name="read_document",
        action="file.read",
        request_fingerprint=fingerprint,
        idempotency_key=idem,
    )
    with pytest.raises(OperationInProgress, match="paca_operation_in_progress"):
        second.claim_execution(
            thread_id=thread_id,
            tool_call_id=call_id,
            tool_name="read_document",
            action="file.read",
            request_fingerprint=fingerprint,
            idempotency_key=idem,
        )

    first.complete_execution(
        thread_id=thread_id,
        tool_call_id=call_id,
        claim_token=claim.token,
        status="succeeded",
        result={"execution_id": "persistent-execution", "status": "succeeded"},
        execution_id="persistent-execution",
    )
    replay = second.claim_execution(
        thread_id=thread_id,
        tool_call_id=call_id,
        tool_name="read_document",
        action="file.read",
        request_fingerprint=fingerprint,
        idempotency_key=idem,
    )
    assert replay.token is None
    assert replay.record.status == "succeeded"
    assert replay.record.permit_id == first_record.permit_id


def test_postgres_ledger_rejects_rebinding_of_a_tool_call(postgres_ledgers):
    first, _second = postgres_ledgers
    thread_id = f"rebind-{uuid4()}"
    call_id = f"call-{uuid4()}"
    first.save_authorization(
        thread_id=thread_id,
        tool_call_id=call_id,
        tool_name="read_document",
        action="file.read",
        request_fingerprint="c" * 64,
        permit_id="00000000-0000-0000-0000-000000000123",
        idempotency_key="lg-" + "d" * 64,
    )
    from agent.operation_ledger import OperationLedgerError

    with pytest.raises(OperationLedgerError, match="paca_execution_journal_conflict"):
        first.save_authorization(
            thread_id=thread_id,
            tool_call_id=call_id,
            tool_name="read_document",
            action="file.read",
            request_fingerprint="e" * 64,
            permit_id="00000000-0000-0000-0000-000000000456",
            idempotency_key="lg-" + "d" * 64,
        )


def test_postgres_checkpointer_and_operation_ledger_survive_process_reconstruction():
    if not DATABASE_URL:
        pytest.skip("PACA_AGENT_TEST_DATABASE_URL is not configured")

    # LangGraph checkpoint payloads must use the strict serializer in deployment.
    os.environ["LANGGRAPH_STRICT_MSGPACK"] = "true"
    from langgraph.checkpoint.postgres import PostgresSaver

    thread_id = f"restart-{uuid4()}"
    call_id = f"call-{uuid4()}"
    config = {"configurable": {"thread_id": thread_id}}
    executions: list[tuple[str, str, str]] = []
    authorizations: list[str] = []

    class FirstProcessClient:
        def authorize(self, *, action, resource_id, arguments):
            authorizations.append("first")
            return {"permit_id": "00000000-0000-0000-0000-000000000123"}

        def execute(self, *, action, resource_id, arguments, permit_id, idempotency_key):
            executions.append((permit_id, idempotency_key, "first"))
            raise PACARequestError(None, "transport_outcome_unknown; reconcile before retry")

    class RestartedProcessClient:
        def authorize(self, *, action, resource_id, arguments):
            authorizations.append("unexpected-second-authorization")
            return {"permit_id": "00000000-0000-0000-0000-000000000999"}

        def execute(self, *, action, resource_id, arguments, permit_id, idempotency_key):
            executions.append((permit_id, idempotency_key, "restarted"))
            return {
                "execution_id": "00000000-0000-0000-0000-000000000456",
                "status": "succeeded",
                "result": {"content": "recovered"},
            }

    first_ledger = PostgresOperationLedger(DATABASE_URL, claim_ttl_seconds=60)
    first_ledger.open()
    try:
        with PostgresSaver.from_conn_string(DATABASE_URL) as checkpointer:
            checkpointer.setup()
            with PostgresStore.from_conn_string(DATABASE_URL) as store:
                store.setup()
                graph = build_paca_langgraph_agent(
                    model=FakeModel([tool_call(call_id)]),
                    paca_client=FirstProcessClient(),
                    operations=[operation()],
                    checkpointer=checkpointer,
                    store=store,
                    operation_ledger=first_ledger,
                )
                with pytest.raises(PACARequestError):
                    graph.invoke(
                        {"messages": [HumanMessage(content="Read the permitted report.")]},
                        config,
                    )
    finally:
        first_ledger.close()

    # A fresh process constructs new checkpoint/store/ledger/client objects. The
    # persisted checkpoint resumes the unfinished ToolNode and the transactional
    # ledger supplies the original permit and idempotency key without re-authorizing.
    restarted_ledger = PostgresOperationLedger(DATABASE_URL, claim_ttl_seconds=60)
    restarted_ledger.open()
    try:
        with (
            PostgresSaver.from_conn_string(DATABASE_URL) as checkpointer,
            PostgresStore.from_conn_string(DATABASE_URL) as store,
        ):
            graph = build_paca_langgraph_agent(
                model=FakeModel([AIMessage(content="Recovered after restart.")]),
                paca_client=RestartedProcessClient(),
                operations=[operation()],
                checkpointer=checkpointer,
                store=store,
                operation_ledger=restarted_ledger,
            )
            result = graph.invoke(None, config)
    finally:
        restarted_ledger.close()

    assert result["messages"][-1].content == "Recovered after restart."
    assert authorizations == ["first"]
    assert len(executions) == 2
    assert executions[0][0] == executions[1][0] == "00000000-0000-0000-0000-000000000123"
    assert executions[0][1] == executions[1][1]
    assert executions[0][2] == "first"
    assert executions[1][2] == "restarted"
