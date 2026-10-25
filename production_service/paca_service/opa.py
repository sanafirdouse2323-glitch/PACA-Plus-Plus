from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


class PolicyEngineUnavailable(RuntimeError):
    """OPA could not return a well-formed, expected-revision decision."""


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    policy_revision: str
    decision_id: str | None = None


class OPAClient:
    """HTTP client for a named OPA Data API decision.

    OPA is the policy decision point; this service remains the enforcement point.
    An undefined, malformed, unavailable or unexpected-revision decision fails closed.
    """

    def __init__(
        self,
        base_url: str,
        decision_path: str,
        expected_policy_revision: str,
        timeout_seconds: float = 2.0,
        client: httpx.Client | None = None,
    ) -> None:
        if not decision_path.startswith("/v1/data/"):
            raise ValueError("OPA decision path must use the OPA Data API.")
        self.url = base_url.rstrip("/") + decision_path
        self.expected_policy_revision = expected_policy_revision
        self.client = client or httpx.Client(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        )

    def evaluate(self, input_document: dict[str, Any]) -> PolicyDecision:
        try:
            response = self.client.post(self.url, json={"input": input_document})
        except httpx.RequestError as exc:
            raise PolicyEngineUnavailable("opa_unavailable") from exc
        if response.status_code != 200:
            raise PolicyEngineUnavailable(f"opa_http_{response.status_code}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise PolicyEngineUnavailable("opa_invalid_json") from exc
        result = payload.get("result") if isinstance(payload, dict) else None
        if not isinstance(result, dict) or type(result.get("allow")) is not bool:
            raise PolicyEngineUnavailable("opa_undefined_or_malformed_decision")
        revision = result.get("policy_revision")
        if not isinstance(revision, str) or not revision:
            raise PolicyEngineUnavailable("opa_policy_revision_missing")
        if revision != self.expected_policy_revision:
            raise PolicyEngineUnavailable("opa_policy_revision_mismatch")
        reason = result.get("reason")
        if not isinstance(reason, str) or not reason:
            reason = "policy_denied" if result["allow"] is False else "policy_allowed"
        decision_id = payload.get("decision_id") if isinstance(payload, dict) else None
        if not isinstance(decision_id, str):
            decision_id = None
        return PolicyDecision(
            allowed=result["allow"],
            reason=reason,
            policy_revision=revision,
            decision_id=decision_id,
        )

    def health(self) -> None:
        decision = self.evaluate({
            "principal": {"id": "healthcheck", "tenant_id": "healthcheck",
                          "roles": [], "scopes": [], "tools": []},
            "action": "__paca_healthcheck__",
            "resource": {"id": "healthcheck", "tenant_id": "healthcheck",
                         "owner_id": "", "kind": "healthcheck", "status": "inactive",
                         "attributes": {}},
            "arguments": {},
        })
        if decision.allowed:
            raise PolicyEngineUnavailable("opa_healthcheck_unexpected_allow")

    def close(self) -> None:
        self.client.close()
