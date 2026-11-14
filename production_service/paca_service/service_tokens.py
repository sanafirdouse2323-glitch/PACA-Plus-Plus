from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from urllib.parse import urlsplit

import httpx


class TokenProviderUnavailable(RuntimeError):
    """A service access token could not be obtained or safely reused."""


class ClientCredentialsTokenProvider:
    """Thread-safe OAuth 2.0 client-credentials token cache.

    Uses client_secret_basic, disables redirects and environment proxy inheritance,
    bounds token-response size, and refreshes before expiry. If a refresh attempt
    fails while the cached token is still valid, the valid token may be used until
    its expiry; after expiry, the provider fails closed.
    """

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        *,
        scope: str | None = None,
        timeout_seconds: float = 5.0,
        refresh_skew_seconds: float = 30.0,
        max_response_bytes: int = 65_536,
        client: httpx.Client | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        parts = urlsplit(token_url)
        if parts.scheme not in {"https", "http"} or not parts.hostname:
            raise ValueError("oauth_token_url_must_be_absolute_http_url")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("oauth_token_url_must_not_contain_credentials_query_or_fragment")
        host = parts.hostname.lower().rstrip(".")
        if parts.scheme == "http" and host not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("oauth_token_endpoint_requires_https")
        if not isinstance(client_id, str) or not client_id or any(ch in client_id for ch in "\r\n"):
            raise ValueError("oauth_client_id_invalid")
        if not isinstance(client_secret, str) or not client_secret or any(
            ch in client_secret for ch in "\r\n"
        ):
            raise ValueError("oauth_client_secret_invalid")
        if scope is not None and (
            not isinstance(scope, str)
            or scope.strip() != scope
            or any(ch in scope for ch in "\r\n")
            or len(scope) > 1024
        ):
            raise ValueError("oauth_scope_invalid")
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or timeout_seconds <= 0
            or timeout_seconds > 60
        ):
            raise ValueError("oauth_timeout_must_be_positive_and_at_most_60_seconds")
        if (
            not isinstance(refresh_skew_seconds, (int, float))
            or isinstance(refresh_skew_seconds, bool)
            or refresh_skew_seconds < 0
            or refresh_skew_seconds > 300
        ):
            raise ValueError("oauth_refresh_skew_must_be_between_0_and_300_seconds")
        if (
            not isinstance(max_response_bytes, int)
            or isinstance(max_response_bytes, bool)
            or max_response_bytes < 1
            or max_response_bytes > 1_000_000
        ):
            raise ValueError("oauth_max_response_bytes_must_be_between_1_and_1000000")
        if client is not None and client.follow_redirects:
            raise ValueError("oauth_http_client_must_disable_redirects")

        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.refresh_skew_seconds = float(refresh_skew_seconds)
        self.max_response_bytes = max_response_bytes
        self._clock = clock
        self._lock = threading.Lock()
        self._access_token: str | None = None
        self._expires_at = 0.0
        self._refresh_at = 0.0
        self._retry_at = 0.0
        self._owns_client = client is None
        self.client = client or httpx.Client(
            timeout=httpx.Timeout(float(timeout_seconds)),
            follow_redirects=False,
            trust_env=False,
        )

    def _request_token(self) -> tuple[str, float]:
        form = {"grant_type": "client_credentials"}
        if self.scope:
            form["scope"] = self.scope
        try:
            with self.client.stream(
                "POST",
                self.token_url,
                data=form,
                auth=httpx.BasicAuth(self.client_id, self.client_secret),
                headers={"Accept": "application/json"},
            ) as response:
                if response.status_code != 200:
                    raise TokenProviderUnavailable("oauth_token_endpoint_rejected_request")
                body = bytearray()
                for chunk in response.iter_bytes():
                    if len(body) + len(chunk) > self.max_response_bytes:
                        raise TokenProviderUnavailable("oauth_token_response_too_large")
                    body.extend(chunk)
        except httpx.RequestError as exc:
            raise TokenProviderUnavailable("oauth_token_endpoint_unavailable") from exc

        try:
            payload = json.loads(bytes(body))
        except (ValueError, UnicodeDecodeError) as exc:
            raise TokenProviderUnavailable("oauth_token_response_invalid_json") from exc
        if not isinstance(payload, dict):
            raise TokenProviderUnavailable("oauth_token_response_invalid_shape")

        token = payload.get("access_token")
        token_type = payload.get("token_type")
        lifetime = payload.get("expires_in")
        if (
            not isinstance(token, str)
            or not token
            or any(ch.isspace() or ord(ch) < 33 for ch in token)
        ):
            raise TokenProviderUnavailable("oauth_access_token_invalid")
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise TokenProviderUnavailable("oauth_token_type_not_bearer")
        if (
            not isinstance(lifetime, (int, float))
            or isinstance(lifetime, bool)
            or lifetime <= 0
            or lifetime > 86_400
        ):
            raise TokenProviderUnavailable("oauth_expires_in_invalid")
        return token, float(lifetime)

    def get_token(self) -> str:
        """Return a current access token, refreshing once across concurrent callers."""
        with self._lock:
            now = self._clock()
            if self._access_token is not None and now < self._refresh_at:
                return self._access_token
            if (
                self._access_token is not None
                and now < self._retry_at
                and now < self._expires_at
            ):
                return self._access_token

            try:
                token, lifetime = self._request_token()
            except TokenProviderUnavailable:
                now = self._clock()
                if self._access_token is not None and now < self._expires_at:
                    # A failed proactive refresh must not discard a still-valid token.
                    remaining = self._expires_at - now
                    self._retry_at = now + min(5.0, max(0.1, remaining / 2))
                    return self._access_token
                raise

            now = self._clock()
            self._access_token = token
            self._expires_at = now + lifetime
            refresh_margin = min(self.refresh_skew_seconds, lifetime * 0.1)
            self._refresh_at = self._expires_at - refresh_margin
            self._retry_at = self._refresh_at
            return token

    def close(self) -> None:
        if self._owns_client:
            self.client.close()
