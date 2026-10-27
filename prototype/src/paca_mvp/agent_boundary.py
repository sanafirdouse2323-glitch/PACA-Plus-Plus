"""Fail-closed tool-call boundary for LLM agents.

This module constrains effects, not model thoughts: tool names, actions, and
resources come from trusted server configuration; model-produced arguments are
validated against a small allowlisted schema; every returned payload is labelled
as untrusted external data. Wire the executor to GuardedGateway so identity,
OPA policy, durable permits, and downstream idempotency remain enforced.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
import hashlib
import json
import math
import re
import threading
from typing import Any, Callable, Mapping

from .hardening import HardeningError, EffectOutcomeUnknown


_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_CALL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_KINDS = {"string", "integer", "number", "boolean", "string_list"}
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 20_000
_MAX_JSON_TEXT_CHARS = 1_000_000


class AgentBoundaryError(RuntimeError):
    """A proposed agent tool call was rejected at the trusted boundary."""

    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


class ApprovalRequired(AgentBoundaryError):
    """A tool requires independently verified human approval."""


@dataclass(frozen=True)
class ArgumentSpec:
    """Schema for one scalar or list-of-strings argument.

    Deliberately does not support arbitrary nested objects, URLs, shell commands,
    or dynamic schemas. Add an explicit tool-specific validator when needed.
    """

    kind: str = "string"
    required: bool = True
    max_length: int = 4096
    min_length: int = 0
    max_items: int = 64
    non_whitespace: bool = False
    nullable: bool = False
    choices: tuple[Any, ...] = ()
    minimum: float | None = None
    maximum: float | None = None

    def __post_init__(self) -> None:
        if self.kind not in _KINDS:
            raise ValueError(f"unsupported argument kind: {self.kind!r}")
        if (self.max_length < 0 or self.min_length < 0
                or self.min_length > self.max_length or self.max_items < 0):
            raise ValueError("argument limits are invalid")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("argument minimum cannot exceed maximum")
        if self.kind not in {"integer", "number"} and (
            self.minimum is not None or self.maximum is not None
        ):
            raise ValueError("numeric bounds are only valid for integer/number arguments")
        if not isinstance(self.choices, (tuple, list)):
            raise ValueError("choices must be a tuple or list")
        object.__setattr__(self, "choices", tuple(self.choices))
        if any(not (item is None or type(item) in (str, int, float, bool)) for item in self.choices):
            raise ValueError("choices must contain scalar JSON values")


@dataclass(frozen=True)
class ToolSpec:
    """Trusted, immutable mapping from a model-visible name to one action/resource."""

    name: str
    action: str
    resource: str
    arguments: Mapping[str, ArgumentSpec]
    requires_approval: bool = False
    max_argument_bytes: int = 8192

    def __post_init__(self) -> None:
        for label, value in (("tool name", self.name), ("action", self.action), ("resource", self.resource)):
            if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
                raise ValueError(f"invalid {label}")
        if not isinstance(self.arguments, Mapping):
            raise ValueError("arguments schema must be a mapping")
        checked: dict[str, ArgumentSpec] = {}
        for name, spec in self.arguments.items():
            if not isinstance(name, str) or not _IDENTIFIER.fullmatch(name):
                raise ValueError("invalid argument name in schema")
            if not isinstance(spec, ArgumentSpec):
                raise ValueError("schema values must be ArgumentSpec instances")
            checked[name] = spec
        if self.max_argument_bytes < 1:
            raise ValueError("max_argument_bytes must be positive")
        object.__setattr__(self, "arguments", MappingProxyType(checked))


@dataclass(frozen=True)
class AgentToolResult:
    """Result envelope; payload content is never promoted to trusted instructions."""

    tool: str
    action: str
    resource: str
    request_hash: str
    payload: Any
    trust: str = "untrusted_tool_output"


ApprovalVerifier = Callable[[str, str, str, str, str, str], bool]
Executor = Callable[[str, str, Mapping[str, Any], str], Any]
AuditCallback = Callable[[str, Mapping[str, Any]], None]


def _canonical_json(value: Any) -> str:
    """Serialize strict JSON data with structural and Unicode bounds."""
    nodes = 0
    text_chars = 0

    def inspect(item: Any, depth: int = 0) -> None:
        nonlocal nodes, text_chars
        nodes += 1
        if depth > _MAX_JSON_DEPTH or nodes > _MAX_JSON_NODES:
            raise ValueError("JSON structure exceeds its depth/item limit")
        if isinstance(item, str):
            text_chars += len(item)
            if len(item) > _MAX_JSON_TEXT_CHARS or text_chars > _MAX_JSON_TEXT_CHARS:
                raise ValueError("JSON text exceeds its character limit")
            item.encode("utf-8")
        elif item is None or type(item) in (bool, int):
            return
        elif type(item) is float:
            if not math.isfinite(item):
                raise ValueError("non-finite JSON number")
        elif isinstance(item, list):
            for child in item:
                inspect(child, depth + 1)
        elif isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("JSON object keys must be strings")
                inspect(key, depth + 1)
                inspect(child, depth + 1)
        else:
            raise TypeError("unsupported JSON value")

    try:
        inspect(value)
        rendered = json.dumps(value, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False, allow_nan=False)
        rendered.encode("utf-8")
        return rendered
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError) as exc:
        raise AgentBoundaryError("value is not valid bounded JSON data", "invalid_json") from exc


def _validate_argument(name: str, value: Any, spec: ArgumentSpec) -> None:
    kind = spec.kind
    if value is None and spec.nullable:
        return
    valid = False
    if kind == "string":
        valid = (isinstance(value, str) and spec.min_length <= len(value) <= spec.max_length
                 and (not spec.non_whitespace or bool(value.strip())))
    elif kind == "integer":
        valid = type(value) is int
    elif kind == "number":
        valid = type(value) in (int, float) and math.isfinite(value)
    elif kind == "boolean":
        valid = type(value) is bool
    elif kind == "string_list":
        valid = (isinstance(value, list) and len(value) <= spec.max_items
                 and all(isinstance(item, str) and spec.min_length <= len(item) <= spec.max_length
                         and (not spec.non_whitespace or bool(item.strip())) for item in value))
    if not valid:
        raise AgentBoundaryError(f"invalid value for argument {name!r}", "invalid_argument")
    if spec.choices and value not in spec.choices:
        raise AgentBoundaryError(f"value not allowed for argument {name!r}", "invalid_argument_choice")
    if kind in {"integer", "number"}:
        if spec.minimum is not None and value < spec.minimum:
            raise AgentBoundaryError(f"argument {name!r} is below its minimum", "argument_out_of_range")
        if spec.maximum is not None and value > spec.maximum:
            raise AgentBoundaryError(f"argument {name!r} exceeds its maximum", "argument_out_of_range")


class AgentToolBoundary:
    """Constrain untrusted LLM tool calls before routing to protected effects.

    Instantiate one boundary per agent run. The tools mapping and executor must be
    built from trusted application configuration, never from model output. For
    production, the executor should call GuardedGateway with verified caller
    identity, trusted context, OPA, a durable store, and a fixed adapter.
    """

    def __init__(
        self,
        tools: Mapping[str, ToolSpec],
        executor: Executor,
        *,
        approval_verifier: ApprovalVerifier | None = None,
        audit: AuditCallback | None = None,
        max_calls_per_run: int = 20,
        max_total_argument_bytes: int = 64 * 1024,
        max_result_bytes: int = 32 * 1024,
    ) -> None:
        if not isinstance(tools, Mapping) or not tools:
            raise ValueError("at least one trusted tool must be configured")
        if not callable(executor):
            raise ValueError("executor must be callable")
        if max_calls_per_run < 1 or max_total_argument_bytes < 1 or max_result_bytes < 1:
            raise ValueError("run and payload limits must be positive")
        checked: dict[str, ToolSpec] = {}
        for name, spec in tools.items():
            if not isinstance(name, str) or not isinstance(spec, ToolSpec) or name != spec.name:
                raise ValueError("each tool mapping key must exactly match its ToolSpec.name")
            checked[name] = spec
        self._tools = checked
        self._executor = executor
        self._approval_verifier = approval_verifier
        self._audit = audit
        self._max_calls = max_calls_per_run
        self._max_total_bytes = max_total_argument_bytes
        self._max_result_bytes = max_result_bytes
        self._calls = 0
        self._argument_bytes = 0
        self._records: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    def _emit(self, event: str, *, call_id: str, tool: str | None = None,
              request_hash: str | None = None, reason: str | None = None) -> None:
        # Never log model text, argument values, credentials, approval tokens, or tool output.
        if self._audit is not None:
            details: dict[str, Any] = {"call_id": call_id}
            if tool is not None:
                details["tool"] = tool
            if request_hash is not None:
                details["request_hash"] = request_hash
            if reason is not None:
                details["reason"] = reason
            self._audit(event, details)

    def _reject(self, message: str, code: str, *, call_id: str, tool: str | None = None,
                request_hash: str | None = None) -> None:
        self._emit("agent_tool_call_blocked", call_id=call_id, tool=tool,
                    request_hash=request_hash, reason=code)
        error_type = ApprovalRequired if code == "approval_required" else AgentBoundaryError
        raise error_type(message, code)

    def invoke(self, tool_call: Mapping[str, Any], *, call_id: str,
               approval_token: str | None = None,
               approval_subject: str | None = None) -> AgentToolResult:
        """Validate and invoke a model-proposed tool call.

        call_id must be generated by the trusted orchestrator, not the model.
        Approval tokens and approval_subject must come from trusted application
        state, not model output.
        """
        if not isinstance(call_id, str) or not _CALL_ID.fullmatch(call_id):
            raise AgentBoundaryError("invalid orchestrator call id", "invalid_call_id")
        with self._lock:
            if self._calls >= self._max_calls:
                self._reject("agent tool-call budget exhausted", "call_budget_exhausted", call_id=call_id)
            self._calls += 1

        if not isinstance(tool_call, Mapping):
            self._reject("tool call must be an object", "invalid_tool_call", call_id=call_id)
        if (any(not isinstance(key, str) for key in tool_call.keys())
                or set(tool_call) != {"tool", "arguments"}):
            self._reject("tool call must contain only 'tool' and 'arguments'",
                         "unexpected_tool_fields", call_id=call_id)
        name = tool_call.get("tool")
        if not isinstance(name, str) or not _IDENTIFIER.fullmatch(name):
            self._reject("invalid tool name", "invalid_tool_name", call_id=call_id)
        spec = self._tools.get(name)
        if spec is None:
            self._reject("tool is not allowlisted", "tool_not_allowlisted", call_id=call_id, tool=name)

        arguments = tool_call.get("arguments")
        if not isinstance(arguments, Mapping):
            self._reject("tool arguments must be an object", "invalid_arguments", call_id=call_id, tool=name)
        if any(not isinstance(key, str) for key in arguments.keys()):
            self._reject("argument names must be strings", "invalid_argument_name", call_id=call_id, tool=name)
        supplied = set(arguments)
        unknown = supplied - set(spec.arguments)
        if unknown:
            self._reject("tool arguments contain undeclared fields", "unexpected_arguments", call_id=call_id, tool=name)
        missing = {key for key, rule in spec.arguments.items() if rule.required and key not in supplied}
        if missing:
            self._reject("required tool arguments are missing", "missing_arguments", call_id=call_id, tool=name)

        # Copy list inputs before validation to avoid caller mutation after validation.
        normalized: dict[str, Any] = {
            key: list(value) if isinstance(value, list) else value
            for key, value in arguments.items()
        }
        try:
            for key, value in normalized.items():
                _validate_argument(key, value, spec.arguments[key])
            serialized_args = _canonical_json(normalized)
        except AgentBoundaryError as exc:
            self._reject(str(exc), exc.code, call_id=call_id, tool=name)
        argument_bytes = len(serialized_args.encode("utf-8"))
        if argument_bytes > spec.max_argument_bytes:
            self._reject("tool arguments exceed per-tool size limit", "tool_arguments_too_large",
                         call_id=call_id, tool=name)
        with self._lock:
            if self._argument_bytes + argument_bytes > self._max_total_bytes:
                self._reject("agent argument budget exhausted", "argument_budget_exhausted",
                             call_id=call_id, tool=name)
            self._argument_bytes += argument_bytes

        # Routing is computed only from trusted ToolSpec, never from the LLM.
        request_material = {"tool": spec.name, "action": spec.action,
                            "resource": spec.resource, "arguments": normalized}
        request_hash = hashlib.sha256(_canonical_json(request_material).encode("utf-8")).hexdigest()

        with self._lock:
            prior = self._records.get(call_id)
            if prior is not None:
                if prior["request_hash"] != request_hash:
                    self._reject("call id cannot be rebound to different arguments", "call_id_conflict",
                                 call_id=call_id, tool=name, request_hash=request_hash)
                if prior["state"] == "completed":
                    self._emit("agent_tool_idempotent_replay", call_id=call_id, tool=name,
                               request_hash=request_hash)
                    cached = prior["result"]
                    return AgentToolResult(
                        cached.tool, cached.action, cached.resource, cached.request_hash,
                        json.loads(_canonical_json(cached.payload)),
                    )
                if prior["state"] == "running":
                    self._reject("an identical call is still running", "call_in_progress",
                                 call_id=call_id, tool=name, request_hash=request_hash)
                self._reject("prior call outcome may be unknown; reconcile before retry",
                             "prior_call_failed", call_id=call_id, tool=name, request_hash=request_hash)

        if spec.requires_approval:
            if (not isinstance(approval_subject, str) or not approval_subject.strip()
                    or len(approval_subject) > 512):
                self._reject("high-impact tool requires a trusted approval subject", "approval_required",
                             call_id=call_id, tool=name, request_hash=request_hash)
            verified = False
            if isinstance(approval_token, str) and approval_token and self._approval_verifier is not None:
                try:
                    verified = bool(self._approval_verifier(
                        approval_token, approval_subject, spec.name, spec.action, spec.resource, request_hash
                    ))
                except Exception:
                    verified = False
            if not verified:
                self._reject("this tool requires valid approval bound to this exact request",
                             "approval_required", call_id=call_id, tool=name, request_hash=request_hash)

        with self._lock:
            if call_id in self._records:
                self._reject("call id already reserved", "call_id_conflict",
                             call_id=call_id, tool=name, request_hash=request_hash)
            self._records[call_id] = {"request_hash": request_hash, "state": "running", "result": None}
        try:
            self._emit("agent_tool_call_validated", call_id=call_id, tool=name,
                       request_hash=request_hash)
            raw_result = self._executor(spec.action, spec.resource, normalized, call_id)
            try:
                serialized_result = _canonical_json(raw_result)
            except AgentBoundaryError as exc:
                raise AgentBoundaryError(
                    "tool returned unsupported output after execution; reconcile before retry",
                    "effect_outcome_unknown",
                ) from exc
            if len(serialized_result.encode("utf-8")) > self._max_result_bytes:
                payload: Any = {"error": "tool_result_omitted", "reason": "result_too_large",
                                "effect_may_have_completed": True}
                self._emit("agent_tool_result_omitted", call_id=call_id, tool=name,
                           request_hash=request_hash, reason="result_too_large")
            else:
                payload = json.loads(serialized_result)
            cached_result = AgentToolResult(
                spec.name, spec.action, spec.resource, request_hash,
                json.loads(_canonical_json(payload)),
            )
            public_result = AgentToolResult(
                spec.name, spec.action, spec.resource, request_hash,
                json.loads(_canonical_json(payload)),
            )
            with self._lock:
                self._records[call_id]["state"] = "completed"
                self._records[call_id]["result"] = cached_result
            self._emit("agent_tool_effect_completed", call_id=call_id, tool=name,
                       request_hash=request_hash)
            return public_result
        except AgentBoundaryError:
            with self._lock:
                self._records[call_id]["state"] = "failed"
            raise
        except EffectOutcomeUnknown as exc:
            with self._lock:
                self._records[call_id]["state"] = "failed"
            self._emit("agent_tool_effect_failed", call_id=call_id, tool=name,
                       request_hash=request_hash, reason="effect_outcome_unknown")
            raise AgentBoundaryError(
                "protected gateway reports an unknown effect outcome; reconcile before retry",
                "effect_outcome_unknown",
            ) from exc
        except HardeningError as exc:
            with self._lock:
                self._records[call_id]["state"] = "failed"
            self._emit("agent_tool_gateway_rejected", call_id=call_id, tool=name,
                       request_hash=request_hash, reason=type(exc).__name__)
            raise AgentBoundaryError(
                "protected gateway rejected or could not authorize this tool call", "gateway_rejected"
            ) from exc
        except Exception as exc:
            with self._lock:
                self._records[call_id]["state"] = "failed"
            self._emit("agent_tool_effect_failed", call_id=call_id, tool=name,
                       request_hash=request_hash, reason=type(exc).__name__)
            raise AgentBoundaryError(
                "tool execution failed; the effect outcome may be unknown", "effect_outcome_unknown"
            ) from exc


def build_ticket_create_boundary(
    gateway: Any, credential: str, adapter: Any, *, audit: AuditCallback | None = None,
    max_calls_per_run: int = 20,
) -> AgentToolBoundary:
    """Bind one model-visible ticket tool to the existing guarded gateway.

    Credential, gateway, and adapter are trusted orchestration state, never model
    output. The gateway still performs OIDC, trusted-context, OPA, permit, and
    downstream-adapter checks.
    """
    if not isinstance(credential, str) or not credential.strip():
        raise ValueError("a non-empty caller credential is required")
    if not callable(getattr(gateway, "authorize_and_execute", None)):
        raise ValueError("gateway must expose authorize_and_execute")
    ticket = ToolSpec(
        name="ticket_create", action="ticket.create", resource="ticket-collection:default",
        arguments={
            "title": ArgumentSpec("string", max_length=200, min_length=1, non_whitespace=True),
            "description": ArgumentSpec("string", required=False, max_length=4000, nullable=True),
        },
    )

    def execute(action: str, resource: str, arguments: Mapping[str, Any], call_id: str) -> Any:
        return gateway.authorize_and_execute(
            credential=credential, action=action, resource=resource, arguments=arguments,
            adapter=adapter, idempotency_key=call_id,
        )

    return AgentToolBoundary(
        {ticket.name: ticket}, execute, audit=audit, max_calls_per_run=max_calls_per_run,
    )
