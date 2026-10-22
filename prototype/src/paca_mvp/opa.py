"""Open Policy Agent (OPA) REST decision client.

This module talks to OPA's Data API (POST /v1/data/<decision-path>) and fails
closed on transport/protocol errors. It intentionally does not manage/deploy policies.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import re
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


class OPAError(RuntimeError):
    """OPA could not produce a trustworthy decision."""


@dataclass(frozen=True)
class OPADecision:
    allowed: bool
    reason: str
    result: dict[str, Any]
    http_status: int = 200
    decision_id: str | None = None


class OPAPolicyDecisionPoint:
    """Small, fail-closed client for a named OPA Data API decision.

    Use a loopback OPA sidecar over HTTP or a remotely deployed OPA over HTTPS.
    The OPA management API should not be exposed to untrusted callers.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8181",
        decision_path: str = "paca/authz/decision",
        timeout_seconds: float = 1.5,
        bearer_token: str | None = None,
        allow_insecure_remote_http: bool = False,
        max_response_bytes: int = 1_048_576,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("OPA base_url must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("OPA base_url must not include credentials, query, or fragment")
        loopback = parsed.hostname.lower() in {"127.0.0.1", "::1", "localhost"}
        if parsed.scheme != "https" and not loopback and not allow_insecure_remote_http:
            raise ValueError("Remote OPA must use HTTPS; HTTP is permitted only for loopback")
        path = decision_path.strip("/")
        if not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", path):
            raise ValueError("decision_path must contain only safe path segments")
        if not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_response_bytes < 256:
            raise ValueError("max_response_bytes must be at least 256")
        if bearer_token is not None:
            if (not isinstance(bearer_token, str) or not bearer_token
                    or len(bearer_token) > 8192
                    or any(ord(ch) < 0x21 or ord(ch) > 0x7e for ch in bearer_token)):
                raise ValueError("bearer_token must be a bounded printable ASCII token")
        self.endpoint = base_url.rstrip("/") + "/v1/data/" + path
        self.timeout_seconds = timeout_seconds
        self.bearer_token = bearer_token
        self.max_response_bytes = max_response_bytes

    def evaluate(self, opa_input: dict[str, Any]) -> OPADecision:
        """Return allow only when OPA returns an object with allow exactly true.

        An undefined decision (HTTP 200 without a result) is a denial. Network,
        HTTP, and malformed-response failures raise OPAError so callers can fail closed.
        """
        try:
            if not isinstance(opa_input, dict):
                raise ValueError("OPA input must be an object")
            body = json.dumps(
                {"input": opa_input}, separators=(",", ":"), sort_keys=True,
                ensure_ascii=False, allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise OPAError("OPA input is not finite JSON") from exc
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.bearer_token:
            headers["Authorization"] = "Bearer " + self.bearer_token
        request = Request(self.endpoint, data=body, headers=headers, method="POST")
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                status = response.status
                raw = response.read(self.max_response_bytes + 1)
        except HTTPError as exc:
            # Do not include response bodies in exceptions; they may contain policy data.
            raise OPAError(f"OPA returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError, ssl.SSLError) as exc:
            raise OPAError("OPA decision endpoint unavailable") from exc
        if len(raw) > self.max_response_bytes:
            raise OPAError("OPA response exceeded configured size limit")
        try:
            document = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise OPAError("OPA returned invalid JSON") from exc
        if not isinstance(document, dict):
            raise OPAError("OPA response must be a JSON object")
        if "result" not in document:
            return OPADecision(False, "undefined_decision", {}, status)
        result = document["result"]
        if not isinstance(result, dict):
            raise OPAError("OPA decision result must be an object")
        allowed = result.get("allow") is True
        reason = result.get("reason")
        # Keep audit/API reason codes bounded and free of arbitrary policy output.
        if not isinstance(reason, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", reason):
            reason = "permitted" if allowed else "policy_denied"
        # Copy the response through JSON so caller-owned nested values cannot leak in.
        try:
            clean_result = json.loads(json.dumps(result, allow_nan=False))
        except (TypeError, ValueError) as exc:
            raise OPAError("OPA decision contains non-finite or unsupported values") from exc
        decision_id = document.get("decision_id")
        if not isinstance(decision_id, str) or not decision_id or len(decision_id) > 128:
            decision_id = None
        return OPADecision(allowed, reason, clean_result, status, decision_id)
