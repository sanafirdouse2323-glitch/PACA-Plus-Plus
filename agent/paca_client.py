"""Small host-side client for routing protected agent actions through PACA++.

This is an integration helper, not an LLM agent or an authorization decision point.
The caller must supply an access token from the configured trusted identity provider.
"""
from __future__ import annotations

import ipaddress
import json
import re
import uuid
from typing import Any
from urllib.parse import urlsplit
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
_ACTION_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")


class _NoRedirectHandler(HTTPRedirectHandler):
    """Do not forward bearer credentials or effects across redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PACARequestError(RuntimeError):
    """A PACA++ HTTP request failed; status, body and any issued permit are preserved."""

    def __init__(
        self,
        status: int | None,
        body: dict[str, Any] | str,
        *,
        permit_id: str | None = None,
    ):
        super().__init__(f"PACA++ request failed (status={status})")
        self.status = status
        self.body = body
        # Set by authorize_and_execute when the authorization phase succeeded
        # but the subsequent execution request failed or had an unknown outcome.
        self.permit_id = permit_id


class PACAClient:
    """Two-phase client for the production-service authorization/execution API.

    Use authorize() once, persist the returned permit_id and a stable
    idempotency_key, then call execute(). A retry must reuse BOTH values.
    Calling authorize_and_execute() again obtains a new permit and therefore
    is not a safe retry of a prior execution attempt.
    """

    def __init__(self, base_url: str, access_token: str, timeout: float = 10.0):
        parts = urlsplit(base_url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("base_url_must_be_absolute_http_url")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("base_url_must_not_contain_credentials_query_or_fragment")
        if parts.scheme == "http":
            host = parts.hostname.lower().rstrip(".")
            try:
                loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = host == "localhost"
            if not loopback:
                raise ValueError("https_required_for_non_loopback_hosts")
        if not isinstance(access_token, str) or not access_token or any(ch in access_token for ch in "\r\n"):
            raise ValueError("invalid_access_token")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("timeout_must_be_positive")
        self.base_url = base_url.rstrip("/")
        self.access_token = access_token
        self.timeout = float(timeout)

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
        }
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(
                payload, allow_nan=False, separators=(",", ":")
            ).encode("utf-8")
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        request = Request(
            self.base_url + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            opener = build_opener(_NoRedirectHandler)
            with opener.open(request, timeout=self.timeout) as response:
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
            # The caller cannot infer whether a protected remote operation completed.
            raise PACARequestError(
                None, "transport_outcome_unknown; reconcile before retry"
            ) from exc
        try:
            decoded = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise PACARequestError(None, "invalid_json_response") from exc
        if not isinstance(decoded, dict):
            raise PACARequestError(None, "unexpected_response_shape")
        return decoded

    @staticmethod
    def _validate_operation(
        action: str, resource_id: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if not isinstance(action, str) or not _ACTION_RE.fullmatch(action):
            raise ValueError("invalid_action")
        if not isinstance(resource_id, str) or not resource_id.strip() or "\x00" in resource_id:
            raise ValueError("invalid_resource_id")
        if not isinstance(arguments, dict):
            raise ValueError("arguments_must_be_an_object")
        # Reject NaN/Infinity and unsupported nested values before sending.
        try:
            json.dumps(arguments, allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValueError("arguments_must_be_finite_json") from exc
        return {
            "action": action,
            "resource_id": resource_id,
            "arguments": arguments,
        }

    def authorize(
        self,
        *,
        action: str,
        resource_id: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Obtain a permit; persist permit_id before attempting execution."""
        operation = self._validate_operation(action, resource_id, arguments)
        permit = self._request("POST", "/v1/authorizations", operation)
        permit_id = permit.get("permit_id")
        if not isinstance(permit_id, str) or not permit_id:
            raise PACARequestError(None, "authorization_response_missing_permit_id")
        try:
            uuid.UUID(permit_id)
        except ValueError as exc:
            raise PACARequestError(None, "authorization_response_invalid_permit_id") from exc
        return permit

    def execute(
        self,
        *,
        action: str,
        resource_id: str,
        arguments: dict[str, Any],
        permit_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Execute using a previously issued permit.

        For retries after a timeout or connection loss, reuse the same permit_id
        and idempotency_key. Inspect an 'unknown' response/status and reconcile
        the downstream system; never create a new key to force a retry.
        """
        operation = self._validate_operation(action, resource_id, arguments)
        if not isinstance(permit_id, str) or not permit_id:
            raise ValueError("invalid_permit_id")
        try:
            canonical_permit_id = str(uuid.UUID(permit_id))
        except ValueError as exc:
            raise ValueError("invalid_permit_id") from exc
        if not isinstance(idempotency_key, str) or not _IDEMPOTENCY_RE.fullmatch(idempotency_key):
            raise ValueError("invalid_idempotency_key")
        execution = dict(operation)
        execution["permit_id"] = canonical_permit_id
        return self._request(
            "POST", "/v1/executions", execution, idempotency_key=idempotency_key
        )

    def execution_status(self, execution_id: str) -> dict[str, Any]:
        """Read status metadata for the authenticated caller's execution."""
        try:
            canonical_id = str(uuid.UUID(execution_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("invalid_execution_id") from exc
        return self._request("GET", f"/v1/executions/{canonical_id}")

    def authorize_and_execute(
        self,
        *,
        action: str,
        resource_id: str,
        arguments: dict[str, Any],
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Convenience one-shot call; use authorize()+execute() for durable retries.

        If the execution request fails after a permit was issued, the exception
        carries that permit_id so the caller can retry execute() with the same
        permit and idempotency key rather than accidentally obtaining a new permit.
        """
        if not isinstance(idempotency_key, str) or not _IDEMPOTENCY_RE.fullmatch(idempotency_key):
            raise ValueError("invalid_idempotency_key")
        permit = self.authorize(
            action=action, resource_id=resource_id, arguments=arguments
        )
        permit_id = permit["permit_id"]
        try:
            return self.execute(
                action=action,
                resource_id=resource_id,
                arguments=arguments,
                permit_id=permit_id,
                idempotency_key=idempotency_key,
            )
        except PACARequestError as exc:
            exc.permit_id = permit_id
            raise
