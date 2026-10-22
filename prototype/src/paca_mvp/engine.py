from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import math
import re
from threading import RLock
from typing import Any, Callable
from uuid import uuid4

_MISSING = object()
_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]*$")
_MAX_PERMIT_TTL_SECONDS = 300.0


class PolicyError(ValueError):
    """Raised when a policy is malformed or uses unsupported semantics."""


class AuthorizationError(RuntimeError):
    """Raised when a protected effect cannot safely be executed."""


@dataclass(frozen=True)
class Rule:
    id: str
    effect: str
    action: str
    conditions: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class Policy:
    version: str
    rules: tuple[Rule, ...]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        if not isinstance(data, dict):
            raise PolicyError("Policy must be a mapping.")
        version = data.get("version")
        if not isinstance(version, str) or not version.strip():
            raise PolicyError("Policy requires a non-empty version.")
        raw_rules = data.get("rules")
        if not isinstance(raw_rules, list):
            raise PolicyError("Policy 'rules' must be a list.")
        rules: list[Rule] = []
        seen_ids: set[str] = set()
        for raw in raw_rules:
            if not isinstance(raw, dict):
                raise PolicyError("Each rule must be a mapping.")
            rid, effect, action = raw.get("id"), raw.get("effect"), raw.get("action")
            if not isinstance(rid, str) or not rid.strip() or rid in seen_ids:
                raise PolicyError("Each rule needs a unique, non-empty id.")
            seen_ids.add(rid)
            if effect not in {"permit", "deny"}:
                raise PolicyError(f"Rule {rid!r}: effect must be 'permit' or 'deny'.")
            if not isinstance(action, str) or not _IDENTIFIER.fullmatch(action):
                raise PolicyError(f"Rule {rid!r}: action must be a simple exact identifier.")
            conditions = raw.get("conditions", [])
            if not isinstance(conditions, list):
                raise PolicyError(f"Rule {rid!r}: conditions must be a list.")
            if effect == "permit" and not conditions:
                raise PolicyError(f"Rule {rid!r}: permit rules require at least one condition.")
            checked: list[dict[str, Any]] = []
            for condition in conditions:
                if not isinstance(condition, dict):
                    raise PolicyError(f"Rule {rid!r}: each condition must be a mapping.")
                path, op = condition.get("path"), condition.get("op")
                if not isinstance(path, str) or not path or any(not p for p in path.split(".")):
                    raise PolicyError(f"Rule {rid!r}: condition requires a valid dotted path.")
                if op not in {"eq", "ne", "in", "contains", "gte", "lte"}:
                    raise PolicyError(f"Rule {rid!r}: unsupported operator {op!r}.")
                if "value" not in condition and "value_from_path" not in condition:
                    raise PolicyError(f"Rule {rid!r}: condition requires value or value_from_path.")
                if "value" in condition and "value_from_path" in condition:
                    raise PolicyError(f"Rule {rid!r}: use value or value_from_path, not both.")
                if "value_from_path" in condition:
                    other = condition["value_from_path"]
                    if not isinstance(other, str) or not other or any(not p for p in other.split(".")):
                        raise PolicyError(f"Rule {rid!r}: invalid value_from_path.")
                # Copy nested JSON-compatible policy values so later edits to the caller's
                # input cannot silently change the policy after validation.
                try:
                    copied = json.loads(json.dumps(condition, allow_nan=False))
                except (TypeError, ValueError) as exc:
                    raise PolicyError(f"Rule {rid!r}: condition values must be JSON-compatible.") from exc
                checked.append(copied)
            rules.append(Rule(rid, effect, action, tuple(checked)))
        return cls(version=version, rules=tuple(rules))


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    matched_rules: tuple[str, ...] = ()
    permit_id: str | None = None
    policy_version: str | None = None


@dataclass
class _Permit:
    action: str
    resource: str
    policy_version: str
    policy_fingerprint: str
    state_version: int
    expires_at: datetime
    principal_id: str | None = None
    arguments_digest: str | None = None
    consumed: bool = False


def _resolve(context: dict[str, Any], dotted_path: str) -> Any:
    current: Any = context
    for segment in dotted_path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return _MISSING
        current = current[segment]
    return current


def _copy_policy(policy: Policy) -> Policy:
    """Create a validated snapshot so caller-owned nested dictionaries cannot mutate live policy."""
    if not isinstance(policy, Policy):
        raise PolicyError("AuthorizationEngine requires a validated Policy.")
    return Policy.from_dict({
        "version": policy.version,
        "rules": [
            {"id": rule.id, "effect": rule.effect, "action": rule.action,
             "conditions": list(rule.conditions)}
            for rule in policy.rules
        ],
    })


def _policy_fingerprint(policy: Policy) -> str:
    """Fingerprint policy content as well as its declared version label."""
    payload = {
        "version": policy.version,
        "rules": [
            {"id": rule.id, "effect": rule.effect, "action": rule.action,
             "conditions": list(rule.conditions)}
            for rule in policy.rules
        ],
    }
    return _canonical_digest(payload)


def _canonical_digest(value: Any) -> str:
    """Hash JSON arguments deterministically; reject NaN and non-JSON objects."""
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("arguments_must_be_finite_json") from exc
    return sha256(encoded).hexdigest()


def _compare(actual: Any, condition: dict[str, Any], context: dict[str, Any]) -> bool:
    if actual is _MISSING:
        return False
    if "value_from_path" in condition:
        expected = _resolve(context, condition["value_from_path"])
        if expected is _MISSING:
            return False
    else:
        expected = condition["value"]
    op = condition["op"]
    try:
        if op == "eq":
            return type(actual) is type(expected) and actual == expected
        if op == "ne":
            return type(actual) is type(expected) and actual != expected
        if op == "in":
            return isinstance(expected, (list, tuple, set, str)) and actual in expected
        if op == "contains":
            return isinstance(actual, (list, tuple, set, str)) and expected in actual
        if op == "gte":
            return type(actual) is type(expected) and actual >= expected
        if op == "lte":
            return type(actual) is type(expected) and actual <= expected
    except (TypeError, ValueError):
        return False
    return False


class AuthorizationEngine:
    """In-memory research engine; not a distributed or production authorization service.

    The legacy authorize/execute API remains for the existing MVP examples. New code
    should use authorize_operation/execute_operation so permits bind a principal and
    canonicalized operation arguments as well as action and resource.
    """

    def __init__(self, policy: Policy):
        self._policy = _copy_policy(policy)
        self._policy_fingerprint = _policy_fingerprint(self._policy)
        self._state_version = 0
        self._permits: dict[str, _Permit] = {}
        self._lock = RLock()
        self.audit_log: list[dict[str, Any]] = []

    @property
    def policy_version(self) -> str:
        with self._lock:
            return self._policy.version

    @property
    def state_version(self) -> int:
        with self._lock:
            return self._state_version

    def update_policy(self, policy: Policy) -> None:
        with self._lock:
            snapshot = _copy_policy(policy)
            fingerprint = _policy_fingerprint(snapshot)
            self._policy = snapshot
            self._policy_fingerprint = fingerprint
            self.audit_log.append({"event": "policy_updated", "policy_version": snapshot.version,
                                   "policy_fingerprint": fingerprint})

    def advance_state(self) -> int:
        with self._lock:
            self._state_version += 1
            self.audit_log.append({"event": "state_advanced", "state_version": self._state_version})
            return self._state_version

    def authorize(
        self,
        action: str,
        resource: str,
        context: dict[str, Any],
        ttl_seconds: float = 30.0,
        *,
        principal_id: str | None = None,
        arguments: Any = None,
    ) -> Decision:
        """Evaluate a request. Supplying principal_id and arguments enables operation binding."""
        if not isinstance(action, str) or not _IDENTIFIER.fullmatch(action):
            return Decision(False, "invalid_action", policy_version=self.policy_version)
        if not isinstance(resource, str) or not resource.strip():
            return Decision(False, "invalid_resource", policy_version=self.policy_version)
        if not isinstance(context, dict):
            return Decision(False, "invalid_context", policy_version=self.policy_version)
        try:
            valid_ttl = (
                not isinstance(ttl_seconds, bool)
                and isinstance(ttl_seconds, (int, float))
                and math.isfinite(float(ttl_seconds))
                and 0 < ttl_seconds <= _MAX_PERMIT_TTL_SECONDS
            )
        except (OverflowError, TypeError, ValueError):
            valid_ttl = False
        if not valid_ttl:
            return Decision(False, "invalid_permit_ttl", policy_version=self.policy_version)
        if (principal_id is None) != (arguments is None):
            return Decision(False, "principal_and_arguments_must_be_supplied_together",
                            policy_version=self.policy_version)
        if principal_id is not None:
            if not isinstance(principal_id, str) or not principal_id.strip():
                return Decision(False, "invalid_principal", policy_version=self.policy_version)
            try:
                arguments_digest = _canonical_digest(arguments)
            except ValueError:
                return Decision(False, "invalid_arguments", policy_version=self.policy_version)
        else:
            arguments_digest = None

        with self._lock:
            matching: list[Rule] = []
            for rule in self._policy.rules:
                if rule.action != action:
                    continue
                if all(_compare(_resolve(context, c["path"]), c, context) for c in rule.conditions):
                    matching.append(rule)
            denied = [r for r in matching if r.effect == "deny"]
            permits = [r for r in matching if r.effect == "permit"]
            if denied:
                self.audit_log.append({
                    "event": "denied", "action": action, "resource": resource,
                    "reason": "deny_override", "matched_rules": [r.id for r in denied],
                    "policy_version": self._policy.version,
                })
                return Decision(False, "deny_override", tuple(r.id for r in denied), None, self._policy.version)
            if not permits:
                self.audit_log.append({
                    "event": "denied", "action": action, "resource": resource,
                    "reason": "no_matching_permit", "policy_version": self._policy.version,
                })
                return Decision(False, "no_matching_permit", (), None, self._policy.version)
            permit_id = uuid4().hex
            self._permits[permit_id] = _Permit(
                action=action, resource=resource, policy_version=self._policy.version,
                policy_fingerprint=self._policy_fingerprint, state_version=self._state_version,
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
                principal_id=principal_id, arguments_digest=arguments_digest,
            )
            self.audit_log.append({
                "event": "permit_issued", "permit_id": permit_id, "action": action,
                "resource": resource, "matched_rules": [r.id for r in permits],
                "policy_version": self._policy.version, "state_version": self._state_version,
                "principal_id": principal_id,
                "arguments_digest": arguments_digest,
            })
            return Decision(True, "permitted", tuple(r.id for r in permits), permit_id, self._policy.version)

    def authorize_operation(
        self, principal_id: str, action: str, resource: str, arguments: Any,
        context: dict[str, Any], ttl_seconds: float = 30.0,
    ) -> Decision:
        """Authorize an operation while binding the permit to principal and exact JSON arguments."""
        return self.authorize(
            action, resource, context, ttl_seconds,
            principal_id=principal_id, arguments=arguments,
        )

    def execute(
        self,
        permit_id: str,
        action: str,
        resource: str,
        effect: Callable[[], Any],
        *,
        principal_id: str | None = None,
        arguments: Any = None,
    ) -> Any:
        """Validate, consume, and invoke an effect under the local commit lock.

        The lock only serializes this engine's local state and callback. It is not a
        distributed transaction and cannot roll back a partially completed remote effect.
        """
        if not callable(effect):
            raise AuthorizationError("effect_not_callable")
        with self._lock:
            permit = self._permits.get(permit_id)
            if permit is None:
                raise AuthorizationError("unknown_permit")
            if permit.consumed:
                raise AuthorizationError("permit_replayed")
            if permit.principal_id is None or permit.arguments_digest is None:
                raise AuthorizationError("operation_binding_required")
            if datetime.now(timezone.utc) >= permit.expires_at:
                self.audit_log.append({"event": "permit_rejected", "permit_id": permit_id,
                                       "reason": "permit_expired"})
                raise AuthorizationError("permit_expired")
            if action != permit.action or resource != permit.resource:
                raise AuthorizationError("action_or_resource_mismatch")
            if permit.principal_id is not None:
                if principal_id != permit.principal_id:
                    raise AuthorizationError("principal_mismatch")
                try:
                    digest = _canonical_digest(arguments)
                except ValueError as exc:
                    raise AuthorizationError("invalid_arguments") from exc
                if digest != permit.arguments_digest:
                    raise AuthorizationError("arguments_mismatch")
            elif principal_id is not None or arguments is not None:
                raise AuthorizationError("permit_binding_mode_mismatch")
            if permit.policy_fingerprint != self._policy_fingerprint:
                raise AuthorizationError("stale_policy")
            if permit.state_version != self._state_version:
                raise AuthorizationError("stale_state")
            permit.consumed = True
            self.audit_log.append({
                "event": "effect_authorized", "permit_id": permit_id,
                "action": action, "resource": resource,
                "policy_version": self._policy.version, "state_version": self._state_version,
                "principal_id": permit.principal_id,
                "arguments_digest": permit.arguments_digest,
            })
            try:
                result = effect()
            except Exception as exc:
                self.audit_log.append({
                    "event": "effect_failed", "permit_id": permit_id,
                    "error_type": type(exc).__name__,
                })
                raise
            self.audit_log.append({
                "event": "effect_completed", "permit_id": permit_id,
                "action": action, "resource": resource,
            })
            return result

    def execute_operation(
        self, permit_id: str, principal_id: str, action: str, resource: str,
        arguments: Any, effect: Callable[[], Any],
    ) -> Any:
        """Execute only the principal/action/resource/arguments tuple that was authorized."""
        return self.execute(
            permit_id, action, resource, effect,
            principal_id=principal_id, arguments=arguments,
        )
