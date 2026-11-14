from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from .service_tokens import ClientCredentialsTokenProvider, TokenProviderUnavailable


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
        bearer_token: str | None = None,
        max_response_bytes: int = 1_000_000,
        token_provider: ClientCredentialsTokenProvider | None = None,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("OPA base URL must be absolute HTTP(S).")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("OPA base URL must not contain credentials, query or fragment.")
        host = parts.hostname.lower().rstrip(".")
        local_hosts = {"localhost", "127.0.0.1", "::1", "opa"}
        if parts.scheme == "http" and host not in local_hosts:
            raise ValueError("remote OPA must use HTTPS.")
        if token_provider is not None and not isinstance(
            token_provider, ClientCredentialsTokenProvider
        ):
            raise TypeError("OPA token_provider must be a ClientCredentialsTokenProvider.")
        if bearer_token is not None and token_provider is not None:
            raise ValueError("configure either a static OPA bearer token or an OAuth token provider, not both.")
        if host not in local_hosts and not bearer_token and token_provider is None:
            raise ValueError("remote OPA requires a configured service credential.")
        if bearer_token is not None and (
            not isinstance(bearer_token, str)
            or not bearer_token
            or bearer_token.strip() != bearer_token
            or any(ch.isspace() for ch in bearer_token)
        ):
            raise ValueError("OPA bearer token must be a non-whitespace string.")
        if not decision_path.startswith("/v1/data/") or "?" in decision_path or "#" in decision_path:
            raise ValueError("OPA decision path must use the OPA Data API without query or fragment.")
        if client is not None and client.follow_redirects:
            raise ValueError("OPA HTTP client must disable redirects.")
        if not isinstance(max_response_bytes, int) or isinstance(max_response_bytes, bool) or max_response_bytes < 1:
            raise ValueError("OPA max_response_bytes must be a positive integer.")
        self.url = base_url.rstrip("/") + decision_path
        self.expected_policy_revision = expected_policy_revision
        self.bearer_token = bearer_token
        self.token_provider = token_provider
        self.max_response_bytes = max_response_bytes
        self.client = client or httpx.Client(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        )

    def evaluate(self, input_document: dict[str, Any]) -> PolicyDecision:
        headers = {}
        try:
            access_token = self.bearer_token
            if self.token_provider is not None:
                access_token = self.token_provider.get_token()
            if access_token:
                headers["Authorization"] = f"Bearer {access_token}"
            with self.client.stream("POST", self.url, json={"input": input_document}, headers=headers) as response:
                if response.status_code != 200:
                    raise PolicyEngineUnavailable(f"opa_http_{response.status_code}")
                body = bytearray()
                for chunk in response.iter_bytes():
                    if len(body) + len(chunk) > self.max_response_bytes:
                        raise PolicyEngineUnavailable("opa_response_too_large")
                    body.extend(chunk)
        except TokenProviderUnavailable as exc:
            raise PolicyEngineUnavailable("opa_credentials_unavailable") from exc
        except httpx.RequestError as exc:
            raise PolicyEngineUnavailable("opa_unavailable") from exc
        try:
            payload = json.loads(bytes(body))
        except (ValueError, UnicodeDecodeError) as exc:
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
        if self.token_provider is not None:
            self.token_provider.close()
