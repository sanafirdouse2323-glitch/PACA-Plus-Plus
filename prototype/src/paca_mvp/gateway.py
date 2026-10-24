"""Fail-closed authorization gateway and fixed-destination HTTP tool adapter."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import math
import re
import ssl
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .durable import (
    IdempotencyConflict,
    OperationOutcomeUnknown,
    OperationStateError,
    canonical_digest,
    canonical_json,
    strict_json_loads,
)
from .identity import (
    AuthenticatedPrincipal,
    AuthorizationContextProvider,
    ContextRetrievalError,
)
from .opa import OPAError, OPADecision, OPAPolicyDecisionPoint


_ACTION_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]*$")
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_ARGUMENT_BYTES = 262_144
_MAX_TOOL_RESPONSE_BYTES = 1_048_576


class AuthorizationDenied(RuntimeError):
    """The OPA decision was a denial."""


class PolicyEvaluationFailed(RuntimeError):
    """Authorization could not be evaluated; the request was not dispatched."""


class OperationOutcomeUnresolved(RuntimeError):
    """The external action may have happened; do not automatically resubmit it."""

    def __init__(self, message: str, operation_id: str | None = None):
        super().__init__(message)
        self.operation_id = operation_id


class ContextChanged(RuntimeError):
    """Trusted context changed between the initial check and dispatch."""


class RemoteToolError(RuntimeError):
    """A fixed-destination protected tool/API failed or returned an invalid response."""


@dataclass(frozen=True)
class ActionRequest:
    operation_id: str
    idempotency_key: str
    principal: AuthenticatedPrincipal
    action: str
    resource: str
    arguments: dict[str, Any]
    opa_input: dict[str, Any]

    @property
    def downstream_idempotency_key(self) -> str:
        """Stable downstream key namespaced by verified issuer and principal."""
        material = canonical_json({
            "issuer": self.principal.issuer,
            "subject": self.principal.subject,
            "client_idempotency_key": self.idempotency_key,
        })
        return sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class GatewayResult:
    operation_id: str
    status: str
    result: Any
    replayed: bool
    policy_reason: str


class ProtectedToolGateway:
    """Enforce OPA authorization before dispatch to registered server-side handlers.

    Untrusted callers choose an action/resource/arguments, never a handler or endpoint.
    Each call authenticates, loads server-side attributes, evaluates OPA, records a
    durable idempotency operation, refreshes attributes and re-evaluates immediately
    before claiming the operation for dispatch. External effects are never retried here.
    """

    def __init__(
        self,
        *,
        authenticator: Any,
        context_provider: AuthorizationContextProvider,
        policy_decision_point: OPAPolicyDecisionPoint,
        operation_store: Any,
        permit_ttl_seconds: float = 30.0,
    ) -> None:
        self.authenticator = authenticator
        self.context_provider = context_provider
        self.policy_decision_point = policy_decision_point
        self.operation_store = operation_store
        self.permit_ttl_seconds = permit_ttl_seconds
        self._handlers: dict[str, Callable[[ActionRequest], Any]] = {}
        try:
            valid_ttl = (not isinstance(permit_ttl_seconds, bool)
                         and isinstance(permit_ttl_seconds, (int, float))
                         and math.isfinite(float(permit_ttl_seconds))
                         and 0 < permit_ttl_seconds <= 300)
        except (OverflowError, TypeError, ValueError):
            valid_ttl = False
        if not valid_ttl:
            raise ValueError("permit_ttl_seconds must be finite and in (0, 300]")

    def register_action(self, action: str, handler: Callable[[ActionRequest], Any]) -> None:
        if not isinstance(action, str) or not _ACTION_RE.fullmatch(action):
            raise ValueError("invalid_action_identifier")
        if not callable(handler):
            raise ValueError("handler_must_be_callable")
        if action in self._handlers:
            raise ValueError("action_already_registered")
        self._handlers[action] = handler

    def get_operation_status(self, authorization_header: str, operation_id: str) -> dict[str, Any]:
        """Return non-sensitive operation status to the authenticated initiating principal."""
        try:
            principal = self.authenticator.authenticate(authorization_header)
        except Exception:
            raise PermissionError("authentication_required") from None
        if not isinstance(operation_id, str) or not re.fullmatch(r"[0-9a-f]{32}", operation_id):
            raise ValueError("invalid_operation_id")
        operation = self.operation_store.get_operation(operation_id)
        # Use the same outward error for absent and other users' records.
        if operation is None or operation.principal_id != principal.storage_id:
            raise LookupError("operation_not_found")
        return {
            "operation_id": operation.operation_id,
            "status": operation.status,
            "action": operation.action,
            "resource": operation.resource,
            "created_at": operation.created_at,
            "expires_at": operation.expires_at,
            "finished_at": operation.finished_at,
            "error_code": operation.error_code,
        }

    @staticmethod
    def _clone_json(value: Any, max_bytes: int = _MAX_ARGUMENT_BYTES) -> Any:
        try:
            encoded = canonical_json(value)
            if len(encoded.encode("utf-8")) > max_bytes:
                raise ValueError("json_payload_too_large")
            return json.loads(encoded)
        except (TypeError, ValueError) as exc:
            raise ValueError("value_must_be_finite_json_within_size_limit") from exc

    def _build_input(
        self, principal: AuthenticatedPrincipal, action: str, resource: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        trusted = self.context_provider.load(principal, action, resource, arguments)
        subject_attributes = dict(trusted.subject_attributes)
        # Verified identity cannot be overwritten by a context callback.
        subject_attributes.update(principal.opa_identity())
        resource_attributes = dict(trusted.resource_attributes)
        resource_attributes["id"] = resource
        return self._clone_json({
            "subject": subject_attributes,
            "action": action,
            "resource": resource_attributes,
            "arguments": arguments,
            "environment": dict(trusted.environment),
        })

    def execute(
        self,
        authorization_header: str,
        *,
        action: str,
        resource: str,
        arguments: Mapping[str, Any],
        idempotency_key: str,
    ) -> GatewayResult:
        """Execute one registered operation, returning a stored result on safe replay."""
        if not isinstance(action, str) or not _ACTION_RE.fullmatch(action):
            raise ValueError("invalid_action_identifier")
        if not isinstance(resource, str) or not resource.strip() or len(resource) > 2048:
            raise ValueError("invalid_resource_identifier")
        if not isinstance(idempotency_key, str) or not _IDEMPOTENCY_RE.fullmatch(idempotency_key):
            raise ValueError("idempotency_key_required_and_must_be_1_to_128_safe_ascii_characters")

        try:
            principal = self.authenticator.authenticate(authorization_header)
        except Exception:
            # Do not leak token-validation detail to the caller.
            self.operation_store.record_denial(None, action, resource, "authentication_failed")
            raise PermissionError("authentication_required") from None

        if action not in self._handlers:
            self.operation_store.record_denial(principal.storage_id, action, resource, "unregistered_action")
            raise AuthorizationDenied("request_denied")
        if not isinstance(arguments, Mapping):
            raise ValueError("arguments_must_be_a_JSON_object")
        args_snapshot = self._clone_json(dict(arguments))
        if not isinstance(args_snapshot, dict):
            raise ValueError("arguments_must_be_a_JSON_object")

        try:
            input_snapshot = self._build_input(principal, action, resource, args_snapshot)
        except Exception:
            self.operation_store.record_denial(principal.storage_id, action, resource, "trusted_context_unavailable")
            raise PolicyEvaluationFailed("trusted_context_unavailable") from None
        try:
            initial_decision = self.policy_decision_point.evaluate(input_snapshot)
        except OPAError:
            self.operation_store.record_denial(principal.storage_id, action, resource, "opa_unavailable")
            raise PolicyEvaluationFailed("policy_decision_unavailable") from None
        if not initial_decision.allowed:
            self.operation_store.record_denial(principal.storage_id, action, resource, initial_decision.reason)
            raise AuthorizationDenied("request_denied")

        try:
            operation, created = self.operation_store.create_or_get(
                idempotency_key=idempotency_key,
                principal_id=principal.storage_id,
                action=action,
                resource=resource,
                arguments_digest=canonical_digest(args_snapshot),
                context_digest=canonical_digest(input_snapshot),
                # Persist only the decision outcome and bounded reason, not arbitrary policy data.
                policy_decision={"allow": True, "reason": initial_decision.reason[:128],
                                 "decision_id": initial_decision.decision_id,
                                 "policy_version": initial_decision.policy_version},
                ttl_seconds=self.permit_ttl_seconds,
            )
        except IdempotencyConflict:
            raise

        if operation.status == "succeeded":
            return GatewayResult(operation.operation_id, "succeeded", operation.response, True,
                                 str(operation.policy_decision.get("reason", "permitted")))
        if not created:
            if operation.status == "unknown":
                raise OperationOutcomeUnresolved("operation_outcome_unknown; reconcile before retry", operation.operation_id)
            if operation.status == "in_progress":
                raise OperationStateError("operation_in_progress")
            if operation.status != "issued":
                raise OperationStateError("idempotency_key_already_used:" + operation.status)
            # An issued row proves claim() had not committed, so no handler was allowed
            # to start through this gateway. Re-authorize and safely resume that request.
            # A claimed row is never resumed automatically; it becomes UNKNOWN on recovery.

        # Re-fetch authoritative attributes immediately before dispatch.
        try:
            current_input = self._build_input(principal, action, resource, args_snapshot)
            current_decision = self.policy_decision_point.evaluate(current_input)
        except Exception:
            self.operation_store.cancel_issued(operation.operation_id, "pre_dispatch_check_unavailable")
            raise PolicyEvaluationFailed("pre_dispatch_authorization_unavailable") from None
        if canonical_digest(current_input) != canonical_digest(input_snapshot):
            self.operation_store.cancel_issued(operation.operation_id, "authorization_context_changed")
            raise ContextChanged("trusted_authorization_context_changed")
        if not current_decision.allowed:
            self.operation_store.cancel_issued(operation.operation_id, "pre_dispatch_policy_denied")
            self.operation_store.record_denial(principal.storage_id, action, resource, current_decision.reason)
            raise AuthorizationDenied("request_denied_at_dispatch")

        try:
            claimed = self.operation_store.claim(
                operation.operation_id,
                policy_decision={"allow": True, "reason": current_decision.reason[:128],
                                 "decision_id": current_decision.decision_id,
                                 "policy_version": current_decision.policy_version},
            )
        except OperationOutcomeUnknown as exc:
            raise OperationOutcomeUnresolved(str(exc)) from exc
        request = ActionRequest(
            operation_id=claimed.operation_id,
            idempotency_key=claimed.idempotency_key,
            principal=principal,
            action=action,
            resource=resource,
            arguments=self._clone_json(args_snapshot),
            opa_input=self._clone_json(current_input),
        )
        try:
            response = self._clone_json(self._handlers[action](request), _MAX_TOOL_RESPONSE_BYTES)
            completed = self.operation_store.complete(operation.operation_id, response)
        except Exception as exc:
            try:
                self.operation_store.mark_unknown(operation.operation_id, type(exc).__name__)
            except Exception:
                # recover_incomplete() can conservatively handle stale in-progress records.
                pass
            raise OperationOutcomeUnresolved(
                "effect_dispatch_outcome_unknown; do not automatically retry; reconcile operation_id="
                + operation.operation_id, operation.operation_id
            ) from exc
        return GatewayResult(completed.operation_id, "succeeded", completed.response, False,
                             current_decision.reason)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward service credentials to a redirect destination.
        return None


class HTTPJsonActionAdapter:
    """Call one preconfigured JSON API; the requester cannot choose the destination.

    The downstream service should enforce its own authorization and deduplicate the
    Idempotency-Key header. A timeout is treated as an unknown outcome upstream.
    """

    def __init__(
        self,
        endpoint: str,
        *,
        service_token_provider: Callable[[], str] | None = None,
        timeout_seconds: float = 5.0,
        allow_insecure_loopback_for_tests: bool = False,
        max_response_bytes: int = _MAX_TOOL_RESPONSE_BYTES,
    ) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("endpoint must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("endpoint must not contain credentials, query, or fragment")
        loopback = parsed.hostname.lower() in {"127.0.0.1", "::1", "localhost"}
        if parsed.scheme != "https" and not (loopback and allow_insecure_loopback_for_tests):
            raise ValueError("HTTP tool endpoints must use HTTPS except explicitly enabled loopback tests")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be finite and positive")
        if max_response_bytes < 256 or max_response_bytes > _MAX_TOOL_RESPONSE_BYTES:
            raise ValueError("max_response_bytes must be between 256 bytes and 1 MiB")
        self.endpoint = endpoint
        self.service_token_provider = service_token_provider
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self._opener = build_opener(_NoRedirect)

    def _service_token(self) -> str | None:
        if self.service_token_provider is None:
            return None
        token = self.service_token_provider()
        if (not isinstance(token, str) or not token
                or len(token) > 8192
                or not re.fullmatch(r"[-A-Za-z0-9._~+/]+=*", token)):
            raise RemoteToolError("downstream_service_credentials_invalid")
        return token

    def preflight(self) -> None:
        """Validate static adapter configuration/credentials before any operation is claimed."""
        self._service_token()

    def __call__(self, operation: ActionRequest) -> Any:
        body = canonical_json({
            "operation_id": operation.operation_id,
            "principal_id": operation.principal.storage_id,
            "principal_issuer": operation.principal.issuer,
            "action": operation.action,
            "resource": operation.resource,
            "arguments": operation.arguments,
        }).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Idempotency-Key": operation.downstream_idempotency_key,
            "X-PACA-Operation-ID": operation.operation_id,
        }
        token = self._service_token()
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        request = Request(self.endpoint, data=body, headers=headers, method="POST")
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                raw = response.read(self.max_response_bytes + 1)
        except HTTPError as exc:
            raise RemoteToolError("downstream_http_status_" + str(exc.code)) from exc
        except (URLError, TimeoutError, OSError, ssl.SSLError) as exc:
            raise RemoteToolError("downstream_transport_failure") from exc
        if len(raw) > self.max_response_bytes:
            raise RemoteToolError("downstream_response_too_large")
        try:
            decoded = strict_json_loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise RemoteToolError("downstream_returned_invalid_or_ambiguous_json") from exc
        try:
            canonical_json(decoded)
        except ValueError as exc:
            raise RemoteToolError("downstream_returned_non_finite_json") from exc
        return decoded
