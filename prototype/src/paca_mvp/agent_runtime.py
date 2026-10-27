"""Reference synchronous orchestration loop for the guarded agent boundaries.

The runtime does not call a model vendor or create authorization policy. The host
supplies a model adapter and retrieval provider; every candidate document is
filtered before context construction, every model-proposed tool call is routed
through GuardedAgentPipeline, and only output approved by the output boundary is
returned. A host can still bypass this runtime through other code paths.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import re
from itertools import islice
from typing import Any, Callable, Iterable, Mapping
from uuid import uuid4
import json

from .agent_boundary import AgentBoundaryError, AgentToolResult
from .content_boundary import (
    ContentBoundaryError,
    GuardedAgentPipeline,
    OutputBlocked,
    ProvenancedDocument,
)


_CALL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DEFAULT_TOOL_ARGUMENT_BYTES = 32 * 1024
_DEFAULT_TOOL_RESULT_BYTES = 32 * 1024
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 20_000


class AgentRuntimeError(RuntimeError):
    """A guarded agent run could not continue safely."""

    def __init__(self, message: str, code: str, *, cause_code: str | None = None):
        super().__init__(message)
        self.code = code
        self.cause_code = cause_code


@dataclass(frozen=True)
class AgentContextItem:
    """Structured model context with an explicit data-trust label.

    Model adapters must preserve these labels when mapping items into a provider's
    request format. The labels help maintain separation; they are not a prompt-
    injection detector and do not replace the effect/output boundaries.
    """

    kind: str
    trust: str
    content: str


@dataclass(frozen=True)
class ModelToolCall:
    """One model-proposed call. It intentionally has no action/resource/call-ID fields."""

    tool: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True)
class ModelTurn:
    """Exactly one of a final answer or one proposed tool call."""

    final_text: str | None = None
    tool_call: ModelToolCall | None = None

    def __post_init__(self) -> None:
        if (self.final_text is None) == (self.tool_call is None):
            raise ValueError("a model turn must contain exactly one of final_text or tool_call")
        if self.final_text is not None and not isinstance(self.final_text, str):
            raise TypeError("final_text must be text")
        if self.tool_call is not None and not isinstance(self.tool_call, ModelToolCall):
            raise TypeError("tool_call must be a ModelToolCall")


@dataclass(frozen=True)
class AgentRunResult:
    """Result released by the guarded runtime; answer has passed OutputBoundary."""

    answer: str
    model_turns: int
    tool_calls: int
    retrieved_document_ids: tuple[str, ...]
    excluded_documents: tuple[tuple[str, str], ...]


ModelAdapter = Callable[
    [tuple[AgentContextItem, ...], tuple[dict[str, Any], ...]],
    ModelTurn,
]
RetrievalProvider = Callable[[str], Iterable[ProvenancedDocument]]
CallIdFactory = Callable[[], str]


def _strict_json_snapshot(value: Any, *, max_bytes: int) -> Any:
    """Copy bounded plain JSON values before untrusted adapter data crosses a gate."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    nodes = 0
    text_characters = 0

    def copy(item: Any, depth: int = 0) -> Any:
        nonlocal nodes, text_characters
        nodes += 1
        if depth > _MAX_JSON_DEPTH or nodes > _MAX_JSON_NODES:
            raise AgentRuntimeError("JSON data exceeds structural limits", "json_structure_too_large")
        if item is None or type(item) is bool:
            return item
        if type(item) is int:
            if item.bit_length() > max_bytes * 4:
                raise AgentRuntimeError("JSON integer exceeds the byte limit", "json_value_too_large")
            return item
        if type(item) is float:
            if not math.isfinite(item):
                raise AgentRuntimeError("non-finite JSON number is not permitted", "invalid_json_value")
            return item
        if type(item) is str:
            if len(item) > max_bytes:
                raise AgentRuntimeError("JSON string exceeds the byte limit", "json_value_too_large")
            text_characters += len(item)
            if text_characters > max_bytes:
                raise AgentRuntimeError("JSON text exceeds the byte limit", "json_value_too_large")
            try:
                item.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise AgentRuntimeError("JSON string contains invalid Unicode", "invalid_unicode") from exc
            return item
        if type(item) is list:
            return [copy(child, depth + 1) for child in item]
        if type(item) is dict:
            result: dict[str, Any] = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise AgentRuntimeError("JSON object keys must be strings", "invalid_json_value")
                copy(key, depth + 1)
                result[key] = copy(child, depth + 1)
            return result
        raise AgentRuntimeError("only plain JSON values are permitted", "invalid_json_value")

    copied = copy(value)
    try:
        rendered = json.dumps(
            copied, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        )
        raw = rendered.encode("utf-8", errors="strict")
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError) as exc:
        raise AgentRuntimeError("value is not valid JSON", "invalid_json_value") from exc
    if len(raw) > max_bytes:
        raise AgentRuntimeError("JSON payload exceeds the byte limit", "json_value_too_large")
    return copied


def _json_text(value: Any, *, max_bytes: int) -> str:
    copied = _strict_json_snapshot(value, max_bytes=max_bytes)
    try:
        rendered = json.dumps(
            copied, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        )
        rendered.encode("utf-8", errors="strict")
        return rendered
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError) as exc:
        raise AgentRuntimeError("value is not valid JSON", "invalid_json_value") from exc


def _validate_text(value: Any, label: str, max_characters: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_characters:
        raise AgentRuntimeError(f"{label} must be non-empty bounded text", f"invalid_{label}")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise AgentRuntimeError(f"{label} contains invalid Unicode", "invalid_unicode") from exc
    return value


class GuardedAgentRuntime:
    """Synchronous reference loop that routes all in-loop effects through guards.

    This is an adapter-neutral integration layer, not a model implementation.
    The retrieval callback may return candidates, but they must already carry
    provenance issued by trusted ingestion. The model callback receives labeled
    context and schemas derived from the same AgentToolBoundary used to execute
    calls. Model-proposed action/resource/call-ID values are never accepted.
    """

    def __init__(
        self,
        *,
        pipeline: GuardedAgentPipeline,
        generate: ModelAdapter,
        retrieve_candidates: RetrievalProvider,
        system_instruction: str,
        max_model_turns: int = 8,
        max_tool_calls: int = 4,
        max_candidate_documents: int = 200,
        max_retrieval_documents: int = 20,
        max_retrieval_characters: int = 40_000,
        max_tool_argument_bytes: int = _DEFAULT_TOOL_ARGUMENT_BYTES,
        max_tool_result_bytes: int = _DEFAULT_TOOL_RESULT_BYTES,
        max_user_input_characters: int = 20_000,
        max_context_items: int = 256,
        max_context_characters: int = 100_000,
        call_id_factory: CallIdFactory | None = None,
    ) -> None:
        if not isinstance(pipeline, GuardedAgentPipeline):
            raise ValueError("pipeline must be a configured GuardedAgentPipeline")
        if not callable(generate) or not callable(retrieve_candidates):
            raise ValueError("generate and retrieve_candidates must be callable")
        instruction = _validate_text(system_instruction, "system_instruction", 20_000)
        positive_ints = {
            "max_model_turns": max_model_turns,
            "max_candidate_documents": max_candidate_documents,
            "max_tool_argument_bytes": max_tool_argument_bytes,
            "max_tool_result_bytes": max_tool_result_bytes,
            "max_user_input_characters": max_user_input_characters,
            "max_context_items": max_context_items,
            "max_context_characters": max_context_characters,
        }
        for name, value in positive_ints.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if isinstance(max_tool_calls, bool) or not isinstance(max_tool_calls, int) or max_tool_calls < 0:
            raise ValueError("max_tool_calls must be a non-negative integer")
        if (
            isinstance(max_retrieval_documents, bool)
            or not isinstance(max_retrieval_documents, int)
            or max_retrieval_documents < 0
            or isinstance(max_retrieval_characters, bool)
            or not isinstance(max_retrieval_characters, int)
            or max_retrieval_characters < 0
        ):
            raise ValueError("retrieval budgets must be non-negative integers")
        if not callable(call_id_factory) and call_id_factory is not None:
            raise ValueError("call_id_factory must be callable")

        # Resolve the schema now. A broken/missing schema fails before any model call.
        try:
            tool_definitions = pipeline.describe_tools()
        except Exception as exc:
            raise ValueError("pipeline must expose schemas derived from its tool boundary") from exc
        if not tool_definitions:
            raise ValueError("at least one guarded tool must be configured")
        names = [item.get("name") for item in tool_definitions if isinstance(item, dict)]
        if len(names) != len(tool_definitions) or len(names) != len(set(names)):
            raise ValueError("tool schemas must have unique names")

        self._pipeline = pipeline
        self._generate = generate
        self._retrieve_candidates = retrieve_candidates
        self._system_instruction = instruction
        self._max_model_turns = max_model_turns
        self._max_tool_calls = max_tool_calls
        self._max_candidate_documents = max_candidate_documents
        self._max_retrieval_documents = max_retrieval_documents
        self._max_retrieval_characters = max_retrieval_characters
        self._max_tool_argument_bytes = max_tool_argument_bytes
        self._max_tool_result_bytes = max_tool_result_bytes
        self._max_user_input_characters = max_user_input_characters
        self._max_context_items = max_context_items
        self._max_context_characters = max_context_characters
        self._call_id_factory = call_id_factory or (lambda: uuid4().hex)

    def _bounded_candidates(self, user_input: str) -> list[ProvenancedDocument]:
        try:
            source = self._retrieve_candidates(user_input)
            if source is None or isinstance(source, (str, bytes, Mapping)):
                raise AgentRuntimeError("retrieval provider must return a bounded iterable of documents",
                                        "invalid_retrieval_result")
            iterator = iter(source)
            candidates = list(islice(iterator, self._max_candidate_documents + 1))
        except AgentRuntimeError:
            raise
        except Exception as exc:
            raise AgentRuntimeError("retrieval provider failed; no model call was made",
                                    "retrieval_provider_failed") from exc
        if len(candidates) > self._max_candidate_documents:
            raise AgentRuntimeError("retrieval candidate budget exceeded", "retrieval_candidate_budget_exceeded")
        return candidates

    def _check_context(self, context: list[AgentContextItem]) -> None:
        if len(context) > self._max_context_items:
            raise AgentRuntimeError("model context item budget exceeded", "context_item_budget_exceeded")
        total = sum(len(item.kind) + len(item.trust) + len(item.content) for item in context)
        if total > self._max_context_characters:
            raise AgentRuntimeError("model context character budget exceeded", "context_character_budget_exceeded")

    def run(self, user_input: str) -> AgentRunResult:
        """Run one interaction and return only output approved by OutputBoundary."""
        user_text = _validate_text(user_input, "user_input", self._max_user_input_characters)
        candidates = self._bounded_candidates(user_text)
        try:
            retrieval = self._pipeline.retrieve(
                candidates,
                max_documents=self._max_retrieval_documents,
                max_total_characters=self._max_retrieval_characters,
            )
        except Exception as exc:
            raise AgentRuntimeError("retrieval candidates failed provenance/policy checks",
                                    "retrieval_rejected") from exc

        context: list[AgentContextItem] = [
            AgentContextItem("system_instruction", "trusted_configuration", self._system_instruction),
            AgentContextItem("user_input", "untrusted_user_input", user_text),
        ]
        for document in retrieval.included:
            content = _json_text({
                "document_id": document.document_id,
                "source": document.source,
                "source_trust": document.trust,
                "text": document.content,
            }, max_bytes=self._max_retrieval_characters * 4 + 4096)
            context.append(AgentContextItem(
                "retrieved_document",
                "untrusted_retrieved_content",
                content,
            ))

        used_call_ids: set[str] = set()
        tool_calls = 0
        for turn_number in range(1, self._max_model_turns + 1):
            self._check_context(context)
            try:
                # Rebuild descriptions each turn so an adapter cannot mutate stored schemas.
                definitions = self._pipeline.describe_tools()
                turn = self._generate(tuple(context), definitions)
            except AgentRuntimeError:
                raise
            except Exception as exc:
                raise AgentRuntimeError("model adapter failed; no answer was released",
                                        "model_adapter_failed") from exc

            if not isinstance(turn, ModelTurn):
                raise AgentRuntimeError("model adapter returned an invalid turn",
                                        "invalid_model_turn")
            if (turn.final_text is None) == (turn.tool_call is None):
                raise AgentRuntimeError("model turn must contain exactly one outcome",
                                        "invalid_model_turn")
            if turn.final_text is not None:
                try:
                    answer = self._pipeline.release_output(turn.final_text)
                except OutputBlocked:
                    # Never return or log the rejected original response here.
                    raise
                except Exception as exc:
                    raise AgentRuntimeError("output boundary failed; no answer was released",
                                            "output_boundary_failed") from exc
                return AgentRunResult(
                    answer=answer,
                    model_turns=turn_number,
                    tool_calls=tool_calls,
                    retrieved_document_ids=tuple(doc.document_id for doc in retrieval.included),
                    excluded_documents=tuple(retrieval.excluded),
                )

            if turn.tool_call is None or not isinstance(turn.tool_call, ModelToolCall):
                raise AgentRuntimeError("model tool call is malformed", "invalid_tool_call")
            if tool_calls >= self._max_tool_calls:
                raise AgentRuntimeError("tool-call budget exhausted; no further effect was attempted",
                                        "tool_call_budget_exhausted")

            call = turn.tool_call
            if not isinstance(call.tool, str) or type(call.arguments) is not dict:
                raise AgentRuntimeError("tool call must contain a tool name and plain JSON object",
                                        "invalid_tool_call")
            arguments = _strict_json_snapshot(call.arguments, max_bytes=self._max_tool_argument_bytes)
            call_id = self._call_id_factory()
            if (
                not isinstance(call_id, str)
                or not _CALL_ID_RE.fullmatch(call_id)
                or call_id in used_call_ids
            ):
                raise AgentRuntimeError("trusted call-ID generator returned an invalid or repeated ID",
                                        "invalid_call_id")
            used_call_ids.add(call_id)

            tool_call_payload = {"tool": call.tool, "arguments": arguments}
            context.append(AgentContextItem(
                "assistant_tool_call",
                "model_generated",
                _json_text(tool_call_payload, max_bytes=self._max_tool_argument_bytes + 1024),
            ))
            try:
                result = self._pipeline.invoke_tool(tool_call_payload, call_id=call_id)
            except AgentBoundaryError as exc:
                raise AgentRuntimeError(
                    "tool boundary rejected the call or reported an uncertain effect; reconcile if required",
                    "tool_call_failed",
                    cause_code=exc.code,
                ) from exc
            except Exception as exc:
                raise AgentRuntimeError(
                    "tool boundary failed; do not assume the external effect did not occur",
                    "tool_call_failed",
                ) from exc
            if not isinstance(result, AgentToolResult):
                raise AgentRuntimeError(
                    "tool boundary returned an invalid result envelope; external effect outcome may be unknown",
                    "invalid_tool_result",
                    cause_code="effect_outcome_unknown",
                )
            try:
                payload = _strict_json_snapshot(result.payload, max_bytes=self._max_tool_result_bytes)
            except AgentRuntimeError as exc:
                raise AgentRuntimeError(
                    "tool result could not be safely copied; external effect outcome may be unknown",
                    "invalid_tool_result",
                    cause_code="effect_outcome_unknown",
                ) from exc
            context.append(AgentContextItem(
                "tool_result",
                "untrusted_tool_output",
                _json_text({
                    "tool": result.tool,
                    "trust": "untrusted_tool_output",
                    "payload": payload,
                }, max_bytes=self._max_tool_result_bytes + 2048),
            ))
            tool_calls += 1

        raise AgentRuntimeError(
            "model-turn budget exhausted before a validated final answer was produced",
            "model_turn_budget_exhausted",
        )
