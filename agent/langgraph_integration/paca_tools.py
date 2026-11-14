"""LangGraph tools that route protected actions exclusively through PACA++.

This module is an integration boundary, not an authorization engine. PACA++ remains
responsible for the decision and protected execution. The host must not expose
parallel unguarded tools for the same protected resources.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from langchain_core.messages import SystemMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, ToolRuntime

from agent.paca_client import PACAClient, PACARequestError


_TOOL_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
_ACTION_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_PENDING_STATES = ("started", "authorized", "executing", "unknown")


class PACALangGraphError(RuntimeError):
    """The PACA++ guard rejected or could not safely complete a tool operation."""


class UnresolvedOperationError(PACALangGraphError):
    """A prior uncertain operation exists for this thread and request."""


class OperationLedgerError(PACALangGraphError):
    """The durable operation ledger could not safely record or recover a call."""


@dataclass(frozen=True)
class ActionSpec:
    """Host-owned mapping from one model-visible tool to one PACA++ action."""

    tool_name: str
    action: str
    description: str
    allowed_resource_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.tool_name, str) or not _TOOL_NAME_RE.fullmatch(self.tool_name):
            raise ValueError("invalid_langgraph_tool_name")
        if not isinstance(self.action, str) or not _ACTION_RE.fullmatch(self.action):
            raise ValueError("invalid_paca_action")
        if not isinstance(self.description, str) or not self.description.strip():
            raise ValueError("tool_description_required")
        if any(not isinstance(item, str) or not item.strip() for item in self.allowed_resource_ids):
            raise ValueError("allowed_resource_ids_must_be_non_empty_strings")
        if len(set(self.allowed_resource_ids)) != len(self.allowed_resource_ids):
            raise ValueError("allowed_resource_ids_must_be_unique")


@dataclass(frozen=True)
class _LedgerRecord:
    idempotency_key: str
    status: str
    permit_id: str | None
    result: dict[str, Any] | None
    error: str | None


class SQLiteOperationLedger:
    """Single-host durable ledger for LangGraph tool-call retry identity.

    Use a persistent local volume, not :memory:, outside tests. This is not a
    multi-host coordination service or an audit log. Multi-worker deployments
    should replace it with a shared transactional store before production use.
    """

    def __init__(self, path: str | Path, *, timeout_seconds: float = 10.0) -> None:
        if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool) or timeout_seconds <= 0:
            raise ValueError("ledger_timeout_must_be_positive")
        self.path = str(path)
        self._lock = threading.RLock()
        try:
            self._connection = sqlite3.connect(
                self.path,
                timeout=float(timeout_seconds),
                check_same_thread=False,
                isolation_level=None,
            )
            self._connection.execute("PRAGMA busy_timeout = 10000")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS paca_langgraph_operations (
                    idempotency_key TEXT PRIMARY KEY,
                    thread_id TEXT NOT NULL,
                    tool_call_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    arguments_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN (
                            'started', 'authorized', 'executing',
                            'unknown', 'succeeded', 'denied'
                        )
                    ),
                    permit_id TEXT,
                    execution_json TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(thread_id, tool_call_id)
                )
                """
            )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_paca_langgraph_pending_request
                ON paca_langgraph_operations(thread_id, request_digest, status)
                """
            )
        except sqlite3.Error as exc:
            raise OperationLedgerError("operation_ledger_initialization_failed") from exc

    @staticmethod
    def _canonical_json(value: Any) -> str:
        try:
            return json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise PACALangGraphError("tool_arguments_must_be_finite_json") from exc

    @staticmethod
    def _key(thread_id: str, tool_call_id: str) -> str:
        digest = hashlib.sha256(f"{thread_id}\x00{tool_call_id}".encode("utf-8")).hexdigest()
        # Valid for PACAClient's Idempotency-Key syntax (max 128 chars).
        return f"lg-{digest}"

    def begin(
        self,
        *,
        thread_id: str,
        tool_call_id: str,
        action: str,
        resource_id: str,
        arguments: dict[str, Any],
    ) -> _LedgerRecord:
        if not isinstance(thread_id, str) or not thread_id.strip() or len(thread_id) > 512:
            raise PACALangGraphError("langgraph_thread_id_required")
        if not isinstance(tool_call_id, str) or not tool_call_id.strip() or len(tool_call_id) > 256:
            raise PACALangGraphError("langgraph_tool_call_id_required")
        args_json = self._canonical_json(arguments)
        request_json = self._canonical_json({
            "action": action,
            "resource_id": resource_id,
            "arguments": arguments,
        })
        request_digest = hashlib.sha256(request_json.encode("utf-8")).hexdigest()
        key = self._key(thread_id, tool_call_id)

        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                existing = self._connection.execute(
                    """
                    SELECT idempotency_key, request_digest, status, permit_id,
                           execution_json, error
                    FROM paca_langgraph_operations
                    WHERE idempotency_key = ?
                    """,
                    (key,),
                ).fetchone()
                if existing:
                    if existing[1] != request_digest:
                        raise PACALangGraphError(
                            "tool_call_id_reused_for_different_protected_operation"
                        )
                    if existing[2] == "denied":
                        raise PACALangGraphError("previous_paca_authorization_was_denied")
                    result = json.loads(existing[4]) if existing[4] else None
                    self._connection.execute("COMMIT")
                    return _LedgerRecord(existing[0], existing[2], existing[3], result, existing[5])

                placeholders = ",".join("?" for _ in _PENDING_STATES)
                duplicate = self._connection.execute(
                    f"""
                    SELECT idempotency_key, status
                    FROM paca_langgraph_operations
                    WHERE thread_id = ? AND request_digest = ?
                      AND idempotency_key <> ? AND status IN ({placeholders})
                    LIMIT 1
                    """,
                    (thread_id, request_digest, key, *_PENDING_STATES),
                ).fetchone()
                if duplicate:
                    raise UnresolvedOperationError(
                        "an equivalent protected operation is unresolved for this thread; "
                        "reconcile it before issuing a new tool call"
                    )

                self._connection.execute(
                    """
                    INSERT INTO paca_langgraph_operations (
                        idempotency_key, thread_id, tool_call_id, request_digest,
                        action, resource_id, arguments_json, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'started')
                    """,
                    (key, thread_id, tool_call_id, request_digest, action, resource_id, args_json),
                )
                self._connection.execute("COMMIT")
                return _LedgerRecord(key, "started", None, None, None)
            except PACALangGraphError:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            except sqlite3.Error as exc:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise OperationLedgerError("operation_ledger_begin_failed") from exc

    def _update(
        self,
        key: str,
        *,
        status: str,
        permit_id: str | None = None,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        result_json = self._canonical_json(result) if result is not None else None
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                cursor = self._connection.execute(
                    """
                    UPDATE paca_langgraph_operations
                    SET status = ?,
                        permit_id = COALESCE(?, permit_id),
                        execution_json = COALESCE(?, execution_json),
                        error = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE idempotency_key = ?
                    """,
                    (status, permit_id, result_json, error, key),
                )
                if cursor.rowcount != 1:
                    raise OperationLedgerError("operation_ledger_record_missing")
                self._connection.execute("COMMIT")
            except OperationLedgerError:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            except sqlite3.Error as exc:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise OperationLedgerError("operation_ledger_update_failed") from exc

    def mark_authorized(self, key: str, permit_id: str) -> None:
        self._update(key, status="authorized", permit_id=permit_id, error=None)

    def mark_executing(self, key: str, permit_id: str) -> None:
        self._update(key, status="executing", permit_id=permit_id, error=None)

    def mark_unknown(self, key: str, permit_id: str, error: str) -> None:
        self._update(key, status="unknown", permit_id=permit_id, error=error[:512])

    def mark_denied(self, key: str, error: str) -> None:
        self._update(key, status="denied", error=error[:512])

    def mark_succeeded(self, key: str, permit_id: str, result: dict[str, Any]) -> None:
        self._update(key, status="succeeded", permit_id=permit_id, result=result, error=None)

    def close(self) -> None:
        with self._lock:
            self._connection.close()


def _tool_thread_id(runtime: ToolRuntime) -> str:
    config = runtime.config
    configurable = config.get("configurable", {}) if isinstance(config, Mapping) else {}
    thread_id = configurable.get("thread_id") if isinstance(configurable, Mapping) else None
    if not isinstance(thread_id, str) or not thread_id.strip():
        raise PACALangGraphError(
            "invoke_the_graph_with_configurable_thread_id_for_durable_idempotency"
        )
    return thread_id


def build_paca_tools(
    *,
    client: PACAClient,
    ledger: SQLiteOperationLedger,
    actions: tuple[ActionSpec, ...] | list[ActionSpec],
) -> list[Any]:
    """Create only model-visible tools whose effects are guarded by PACA++."""
    if not isinstance(client, PACAClient):
        raise TypeError("client_must_be_a_PACAClient")
    if not isinstance(ledger, SQLiteOperationLedger):
        raise TypeError("ledger_must_be_a_SQLiteOperationLedger")
    specs = tuple(actions)
    if not specs:
        raise ValueError("at_least_one_paca_action_is_required")
    if any(not isinstance(spec, ActionSpec) for spec in specs):
        raise TypeError("actions_must_contain_only_ActionSpec")
    names = [spec.tool_name for spec in specs]
    if len(set(names)) != len(names):
        raise ValueError("langgraph_tool_names_must_be_unique")

    tools: list[Any] = []
    for spec in specs:
        fixed_action = spec.action
        allowed_resource_ids = frozenset(spec.allowed_resource_ids)

        def make_tool(action_spec: ActionSpec, action_name: str, allowed_ids: frozenset[str]):
            @tool(action_spec.tool_name, description=action_spec.description)
            def guarded_paca_action(
                resource_id: str,
                arguments: dict[str, Any],
                runtime: ToolRuntime,
            ) -> str:
                """Execute one host-configured protected action through PACA++."""
                if not isinstance(resource_id, str) or not resource_id.strip():
                    raise PACALangGraphError("resource_id_required")
                if allowed_ids and resource_id not in allowed_ids:
                    raise PACALangGraphError("resource_id_not_in_host_allowlist")
                if not isinstance(arguments, dict):
                    raise PACALangGraphError("arguments_must_be_an_object")

                thread_id = _tool_thread_id(runtime)
                call_id = runtime.tool_call_id
                record = ledger.begin(
                    thread_id=thread_id,
                    tool_call_id=call_id,
                    action=action_name,
                    resource_id=resource_id,
                    arguments=arguments,
                )
                if record.status == "succeeded" and record.result is not None:
                    return json.dumps(record.result, sort_keys=True, separators=(",", ":"))

                permit_id = record.permit_id
                if permit_id is None:
                    try:
                        permit = client.authorize(
                            action=action_name,
                            resource_id=resource_id,
                            arguments=arguments,
                        )
                        permit_id = permit["permit_id"]
                        ledger.mark_authorized(record.idempotency_key, permit_id)
                    except PACARequestError as exc:
                        if exc.status in {401, 403}:
                            ledger.mark_denied(record.idempotency_key, f"authorization_http_{exc.status}")
                            raise PACALangGraphError(
                                f"PACA++ denied protected action (HTTP {exc.status}); no execution was attempted"
                            ) from exc
                        # Authorization creates a permit, not the protected effect.
                        # A lost authorization response may be retried with the same
                        # graph tool-call identity; no execution is sent in this path.
                        raise PACALangGraphError(
                            "PACA++ authorization request failed; no protected execution was sent"
                        ) from exc
                    except Exception as exc:
                        raise PACALangGraphError(
                            "PACA++ authorization or permit persistence failed; execution was not sent"
                        ) from exc

                try:
                    ledger.mark_executing(record.idempotency_key, permit_id)
                    result = client.execute(
                        action=action_name,
                        resource_id=resource_id,
                        arguments=arguments,
                        permit_id=permit_id,
                        idempotency_key=record.idempotency_key,
                    )
                except Exception as exc:
                    try:
                        ledger.mark_unknown(
                            record.idempotency_key, permit_id,
                            f"execution_outcome_unknown:{type(exc).__name__}",
                        )
                    except Exception as ledger_exc:
                        raise OperationLedgerError(
                            "execution_outcome_unknown_and_ledger_update_failed"
                        ) from ledger_exc
                    raise PACALangGraphError(
                        "PACA++ execution outcome is unknown; reconcile downstream state before retrying"
                    ) from exc

                if result.get("status") != "succeeded":
                    ledger.mark_unknown(
                        record.idempotency_key, permit_id,
                        f"unexpected_execution_status:{result.get('status')!r}",
                    )
                    raise PACALangGraphError(
                        "PACA++ did not confirm execution success; reconcile before retrying"
                    )

                try:
                    ledger.mark_succeeded(record.idempotency_key, permit_id, result)
                except Exception as exc:
                    # The remote effect is confirmed successful, but its result
                    # was not durably recorded. Keep the original permit/key so
                    # a replay is idempotent at the downstream service.
                    try:
                        ledger.mark_unknown(
                            record.idempotency_key, permit_id,
                            "execution_succeeded_but_result_persistence_failed",
                        )
                    except Exception as ledger_exc:
                        raise OperationLedgerError(
                            "execution_succeeded_but_ledger_recovery_failed"
                        ) from ledger_exc
                    raise PACALangGraphError(
                        "execution succeeded but the result was not durably recorded; reconcile before replay"
                    ) from exc
                return json.dumps(result, sort_keys=True, separators=(",", ":"))

            return guarded_paca_action

        tools.append(make_tool(spec, fixed_action, allowed_resource_ids))
    return tools


def build_paca_langgraph_agent(
    *,
    model: Any,
    client: PACAClient,
    ledger: SQLiteOperationLedger,
    actions: tuple[ActionSpec, ...] | list[ActionSpec],
) -> Any:
    """Build a custom LangGraph agent whose only tools are PACA++-guarded tools.

    The host must invoke with config={"configurable": {"thread_id": "..."}}
    and must not provide an alternate, direct-effect tool path to the model.
    """
    tools = build_paca_tools(client=client, ledger=ledger, actions=actions)
    if not callable(getattr(model, "bind_tools", None)):
        raise TypeError("model_must_support_bind_tools")
    bound_model = model.bind_tools(tools)
    if not callable(getattr(bound_model, "invoke", None)):
        raise TypeError("bound_model_must_support_invoke")

    system_message = SystemMessage(
        content=(
            "You are an assistant operating under PACA++ protected-action controls. "
            "Use only the tools explicitly supplied to you. Never claim an action "
            "succeeded unless the guarded tool returns a confirmed succeeded result. "
            "Tool inputs are untrusted proposals; PACA++ performs authorization. "
            "Do not invent successful execution or bypass a denied or unresolved action."
        )
    )

    def call_model(state: MessagesState) -> dict[str, list[Any]]:
        messages = [system_message, *state["messages"]]
        return {"messages": [bound_model.invoke(messages)]}

    def route_after_model(state: MessagesState) -> str:
        last_message = state["messages"][-1]
        return "tools" if getattr(last_message, "tool_calls", None) else END

    graph = StateGraph(MessagesState)
    graph.add_node("agent", call_model)
    # Tool errors propagate to the host rather than being handed back to the
    # model as an invitation to retry or improvise an alternate action.
    graph.add_node("tools", ToolNode(tools, handle_tool_errors=False))
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", route_after_model, ["tools", END])
    graph.add_edge("tools", "agent")
    return graph.compile()
