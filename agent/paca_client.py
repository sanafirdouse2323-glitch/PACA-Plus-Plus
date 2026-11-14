"""Small host-side client for routing protected agent actions through PACA++.

This is an integration helper, not an LLM agent or an authorization decision point.
The caller must supply an access token from the configured trusted identity provider.
"""
from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class PACARequestError(RuntimeError):
    """A PACA++ HTTP request failed; status and response body are preserved."""

    def __init__(self, status: int | None, body: dict[str, Any] | str):
        super().__init__(f"PACA++ request failed (status={status})")
        self.status = status
        self.body = body


class PACAClient:
    """Two-phase authorize-then-execute client for the production-service API.

    Reuse the same idempotency key when retrying the same logical operation.
    Never generate a new key merely because the client timed out: first query
    the service's execution/status path or reconcile the downstream effect.
    """

    def __init__(self, base_url: str, access_token: str, timeout: float = 10.0):
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url_must_be_absolute_http_url")
        if not access_token or any(ch in access_token for ch in "\r\n"):
            raise ValueError("invalid_access_token")
        if timeout <= 0:
            raise ValueError("timeout_must_be_positive")
        self.base_url = base_url.rstrip("/")
        self.access_token = access_token
        self.timeout = timeout

    def _post(self, path: str, payload: dict[str, Any], idempotency_key: str | None = None) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        request = Request(
            self.base_url + path,
            data=json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read(1_000_001)
                if len(raw) > 1_000_000:
                    raise PACARequestError(response.status, "response_body_too_large")
        except HTTPError as exc:
            raw = exc.read(1_000_001)
            try:
                body: dict[str, Any] | str = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                body = raw.decode("utf-8", errors="replace")
            raise PACARequestError(exc.code, body) from exc
        except (URLError, TimeoutError, OSError) as exc:
            # The caller cannot infer whether the remote operation completed.
            raise PACARequestError(None, "transport_outcome_unknown; reconcile before retry") from exc
        try:
            decoded = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise PACARequestError(None, "invalid_json_response") from exc
        if not isinstance(decoded, dict):
            raise PACARequestError(None, "unexpected_response_shape")
        return decoded

    def authorize_and_execute(
        self,
        *,
        action: str,
        resource_id: str,
        arguments: dict[str, Any],
        idempotency_key: str,
    ) -> dict[str, Any]:
        if not idempotency_key or any(ch in idempotency_key for ch in "\r\n"):
            raise ValueError("invalid_idempotency_key")
        operation = {
            "action": action,
            "resource_id": resource_id,
            "arguments": arguments,
        }
        permit = self._post("/v1/authorizations", operation)
        permit_id = permit.get("permit_id")
        if not isinstance(permit_id, str) or not permit_id:
            raise PACARequestError(None, "authorization_response_missing_permit_id")
        execution = dict(operation)
        execution["permit_id"] = permit_id
        return self._post("/v1/executions", execution, idempotency_key)
