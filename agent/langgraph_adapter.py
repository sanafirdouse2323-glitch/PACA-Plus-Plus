"""LangGraph adapter that routes every registered protected tool through PACA++.

This adapter targets the production_service HTTP gateway through PACAClient.
It is deliberately separate from prototype/src/paca_mvp/agent_runtime.py.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Annotated, Any, TypedDict

from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.tools import StructuredTool
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, ToolRuntime
from pydantic import BaseModel, ConfigDict, Field, create_model

from .paca_client import PACAClient, PACARequestError


_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ACTION_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")


class PACAFrameworkError(RuntimeError):
    """A framework proposal or gateway response failed the PACA integration contract."""


class PACAExecutionOutcomeUnknown(PACAFrameworkError):
    """The gateway could not establish whether the protected effect completed."""

    def __init__(self, execution_id: str | None, message: str = "protected_effect_outcome_unknown"):
        super().__init__(message)
        self.execution_id = execution_id
        self.retry_safe = False


class PACAExecutionFailed(PACAFrameworkError):
    """The gateway reports a terminal failed execution."""


class PACAArgsModel(BaseModel):
    """Base for model-visible input schemas; unknown fields are rejected."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        arbitrary_types_allowed=True,
    )


@dataclass(frozen=True)
class PACAOperation:
    """One explicitly allowlisted tool-to-action mapping.

    The action is fixed by host configuration. The model may supply only fields in
    args_schema; resource_id_field identifies the resource passed separately to PACA.
    """

    name: str
    description: str
    action: str
    resource_id_field: str
    args_schema: type[PACAArgsModel]

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _TOOL_NAME_RE.fullmatch(self.name):
            raise ValueError("invalid_paca_tool_name")
        if not isinstance(self.description, str) or not self.description.strip() or len(self.description) > 1000:
            raise ValueError("invalid_paca_tool_description")
        if not isinstance(self.action, str) or not _ACTION_RE.fullmatch(self.action):
            raise ValueError("invalid_paca_action")
        if not isinstance(self.resource_id_field, str) or not self.resource_id_field:
            raise ValueError("invalid_resource_id_field")
        if not isinstance(self.args_schema, type) or not issubclass(self.args_schema, PACAArgsModel):
            raise ValueError("args_schema_must_extend_PACAArgsModel")
        field = self.args_schema.model_fields.get(self.resource_id_field)
        if field is None or not field.is_required() or field.annotation is not str:
            raise ValueError("resource_id_field_must_be_a_required_string")
        if self.args_schema.model_config.get("extra") != "forbid":
            raise ValueError("paca_tool_schema_must_forbid_extra_fields")


class _AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]


def derive_idempotency_key(thread_id: str, tool_call_id: str) -> str:
    """Create a stable per-thread/per-tool-call idempotency key for graph replay."""
    if not isinstance(thread_id, str) or not thread_id or len(thread_id) > 256:
        raise PACAFrameworkError("langgraph_thread_id_required")
    if not isinstance(tool_call_id, str) or not tool_call_id or len(tool_call_id) > 128:
        raise PACAFrameworkError("langgraph_tool_call_id_required")
    material = f"paca-langgraph-v1\0{thread_id}\0{tool_call_id}".encode("utf-8")
    return "lg-" + hashlib.sha256(material).hexdigest()


def _runtime_args_schema(operation: PACAOperation) -> type[BaseModel]:
    """Add an injected ToolRuntime field without exposing it to the model schema."""
    return create_model(
        f"{operation.args_schema.__name__}LangGraphRuntimeArgs",
        __base__=operation.args_schema,
        runtime=(ToolRuntime, Field(exclude=True, repr=False)),
    )


def build_paca_tools(
    paca_client: PACAClient,
    operations: list[PACAOperation] | tuple[PACAOperation, ...],
) -> list[StructuredTool]:
    """Build only host-allowlisted tools; every tool performs authorize then execute."""
    if not callable(getattr(paca_client, "authorize", None)) or not callable(
        getattr(paca_client, "execute", None)
    ):
        raise TypeError("paca_client_must_expose_authorize_and_execute")

    if not isinstance(operations, (list, tuple)) or not operations:
        raise ValueError("at_least_one_paca_operation_required")
    if any(not isinstance(item, PACAOperation) for item in operations):
        raise TypeError("operations_must_contain_PACAOperation_values")
    names = [item.name for item in operations]
    if len(names) != len(set(names)):
        raise ValueError("duplicate_paca_tool_name")

    tools: list[StructuredTool] = []
    for operation in operations:
        runtime_schema = _runtime_args_schema(operation)

        def invoke(
            runtime: ToolRuntime,
            _operation: PACAOperation = operation,
            **raw_arguments: Any,
        ) -> str:
            operation = _operation
            if not isinstance(runtime, ToolRuntime):
                raise PACAFrameworkError("langgraph_tool_runtime_missing")
            if not isinstance(runtime.config, dict):
                raise PACAFrameworkError("langgraph_runtime_config_missing")
            configurable = runtime.config.get("configurable")
            if not isinstance(configurable, dict):
                raise PACAFrameworkError("langgraph_thread_id_required")
            thread_id = configurable.get("thread_id")
            idempotency_key = derive_idempotency_key(thread_id, runtime.tool_call_id)

            try:
                validated = operation.args_schema.model_validate(raw_arguments, strict=True)
            except Exception as exc:
                raise PACAFrameworkError("paca_tool_arguments_invalid") from exc

            payload = validated.model_dump(mode="json")
            resource_id = payload.pop(operation.resource_id_field, None)
            if (
                not isinstance(resource_id, str)
                or not resource_id.strip()
                or len(resource_id) > 256
                or "\x00" in resource_id
            ):
                raise PACAFrameworkError("paca_resource_id_invalid")
            try:
                json.dumps(payload, allow_nan=False, separators=(",", ":"))
            except (TypeError, ValueError) as exc:
                raise PACAFrameworkError("paca_arguments_not_finite_json") from exc

            permit = paca_client.authorize(
                action=operation.action,
                resource_id=resource_id,
                arguments=payload,
            )
            permit_id = permit.get("permit_id") if isinstance(permit, dict) else None
            if not isinstance(permit_id, str) or not permit_id:
                raise PACAFrameworkError("paca_authorization_response_missing_permit")

            try:
                result = paca_client.execute(
                    action=operation.action,
                    resource_id=resource_id,
                    arguments=payload,
                    permit_id=permit_id,
                    idempotency_key=idempotency_key,
                )
            except PACARequestError as exc:
                # Preserve the permit ID for operator reconciliation and safe retry.
                exc.permit_id = permit_id
                raise

            if not isinstance(result, dict):
                raise PACAFrameworkError("paca_execution_response_invalid")
            status = result.get("status")
            if status == "unknown":
                execution_id = result.get("execution_id")
                raise PACAExecutionOutcomeUnknown(
                    execution_id if isinstance(execution_id, str) else None
                )
            if status == "failed":
                raise PACAExecutionFailed("paca_execution_failed")
            if status != "succeeded":
                raise PACAFrameworkError("paca_execution_status_not_terminal_success")
            try:
                return json.dumps(result, allow_nan=False, sort_keys=True, separators=(",", ":"))
            except (TypeError, ValueError) as exc:
                # An invalid result cannot be represented as a trusted tool observation.
                raise PACAFrameworkError("paca_execution_result_not_finite_json") from exc

        invoke.__name__ = f"paca_{operation.name}"
        invoke.__doc__ = operation.description
        tools.append(
            StructuredTool.from_function(
                func=invoke,
                name=operation.name,
                description=operation.description,
                args_schema=runtime_schema,
                infer_schema=False,
                handle_tool_error=False,
            )
        )
    return tools


def build_paca_langgraph_agent(
    *,
    model: Any,
    paca_client: PACAClient,
    operations: list[PACAOperation] | tuple[PACAOperation, ...],
    checkpointer: BaseCheckpointSaver,
):
    """Compile a serial-tool LangGraph agent with no unguarded tool execution node.

    A checkpointer is mandatory so graph state can be resumed. Use a durable,
    access-controlled checkpointer in deployment; InMemorySaver is for tests only.
    """
    if checkpointer is None:
        raise ValueError("langgraph_checkpointer_required")
    if not callable(getattr(model, "bind_tools", None)):
        raise TypeError("model_must_support_bind_tools")
    if not callable(getattr(model, "invoke", None)):
        raise TypeError("model_must_expose_invoke")

    tools = build_paca_tools(paca_client, operations)
    allowed_names = {tool.name for tool in tools}
    try:
        bound_model = model.bind_tools(tools)
    except Exception as exc:
        raise ValueError("model_tool_binding_failed") from exc
    if not callable(getattr(bound_model, "invoke", None)):
        raise TypeError("bound_model_must_expose_invoke")

    def call_model(state: _AgentState, config: dict[str, Any]) -> dict[str, list[BaseMessage]]:
        messages = state.get("messages")
        if not isinstance(messages, list) or not messages:
            raise PACAFrameworkError("langgraph_messages_required")
        response = bound_model.invoke(messages, config=config)
        if not isinstance(response, AIMessage):
            raise PACAFrameworkError("model_must_return_AIMessage")
        calls = response.tool_calls
        if len(calls) > 1:
            # ToolNode can execute calls concurrently. PACA actions are deliberately
            # serialized so one model turn cannot race multiple protected effects.
            raise PACAFrameworkError("multiple_tool_calls_per_turn_forbidden")
        for call in calls:
            if not isinstance(call, dict) or call.get("name") not in allowed_names:
                raise PACAFrameworkError("unregistered_tool_call_forbidden")
            if not isinstance(call.get("id"), str) or not call["id"]:
                raise PACAFrameworkError("tool_call_id_required")
        return {"messages": [response]}

    def route_after_model(state: _AgentState) -> str:
        last = state["messages"][-1]
        if isinstance(last, AIMessage) and last.tool_calls:
            return "tools"
        return END

    builder = StateGraph(_AgentState)
    builder.add_node("agent", call_model)
    # ToolNode is restricted to the PACA-backed tools constructed above.
    # Exceptions (including unknown outcomes) propagate; they are not handed to
    # the model as recoverable text that might trigger an unsafe retry.
    builder.add_node("tools", ToolNode(tools, handle_tool_errors=False))
    builder.add_edge(START, "agent")
    builder.add_conditional_edges("agent", route_after_model, {"tools": "tools", END: END})
    builder.add_edge("tools", "agent")
    return builder.compile(checkpointer=checkpointer)
