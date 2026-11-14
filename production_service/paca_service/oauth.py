from __future__ import annotations

import json
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

import httpx


class OAuthTokenError(RuntimeError):
    """A service-to-service access token could not be obtained safely."""


@dataclass(frozen=True)
class _CachedToken:
    value: str
    expires_at: float
    refresh_at: float


class OAuthClientCredentialsTokenProvider:
    """Thread-safe OAuth 2.0 client-credentials token cache.

    Tokens are obtained using client_secret_basic or TLS client authentication.
    Client-credentials grants are renewed by obtaining a new access token when
    needed; the provider deliberately does not depend on refresh tokens.
    """

    def __init__(
        self,
        *,
        token_url: str,
        client_id: str,
        client_secret: str | None = None,
        scope: str | None = None,
        resource: str | None = None,
        auth_method: str = "client_secret_basic",
        client_certificate: str | None = None,
        client_private_key: str | None = None,
        ca_bundle: str | None = None,
        timeout_seconds: float = 5.0,
        refresh_skew_seconds: float = 30.0,
        client: httpx.Client | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        parts = urlsplit(token_url)
        if (
            parts.scheme not in {"https", "http"}
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.query
            or parts.fragment
        ):
            raise ValueError("oauth_token_url_must_be_absolute_without_credentials_or_query")
        host = parts.hostname.lower().rstrip(".")
        if parts.scheme == "http" and host not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("https_required_for_remote_oauth_token_endpoint")
        if not isinstance(client_id, str) or not client_id or any(ch.isspace() for ch in client_id):
            raise ValueError("invalid_oauth_client_id")
        if auth_method not in {"client_secret_basic", "tls_client_auth"}:
            raise ValueError("unsupported_oauth_client_auth_method")
        if auth_method == "client_secret_basic":
            if not isinstance(client_secret, str) or not client_secret:
                raise ValueError("oauth_client_secret_required")
        elif client_secret is not None:
            raise ValueError("client_secret_not_used_with_tls_client_auth")
        cert_pair_present = bool(client_certificate) and bool(client_private_key)
        if bool(client_certificate) != bool(client_private_key):
            raise ValueError("oauth_mtls_certificate_and_key_must_be_configured_together")
        if auth_method == "tls_client_auth" and not cert_pair_present:
            raise ValueError("oauth_tls_client_auth_requires_certificate_and_key")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0 < timeout_seconds <= 60
        ):
            raise ValueError("oauth_timeout_must_be_positive_and_at_most_60_seconds")
        if (
            isinstance(refresh_skew_seconds, bool)
            or not isinstance(refresh_skew_seconds, (int, float))
            or not 0 <= refresh_skew_seconds <= 300
        ):
            raise ValueError("oauth_refresh_skew_must_be_between_0_and_300_seconds")
        for label, value in (("scope", scope), ("resource", resource)):
            if value is not None and (
                not isinstance(value, str)
                or not value.strip()
                or any(ch in value for ch in "\r\n\x00")
            ):
                raise ValueError(f"invalid_oauth_{label}")

        self.token_url = token_url
        self.client_id = client_id
        self._client_secret = client_secret
        self.scope = scope
        self.resource = resource
        self.auth_method = auth_method
        self._client_certificate = client_certificate
        self._client_private_key = client_private_key
        self._ca_bundle = ca_bundle
        self.timeout_seconds = float(timeout_seconds)
        self.refresh_skew_seconds = float(refresh_skew_seconds)
        self._clock = clock
        self._condition = threading.Condition()
        self._cached: _CachedToken | None = None
        self._refreshing = False
        self._closed = False
        self._client = client or self._new_http_client()
        self._owns_client = client is None
        if client is not None and client.follow_redirects:
            raise ValueError("oauth_http_client_must_disable_redirects")

    def _ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=self._ca_bundle)
        if self._client_certificate:
            context.load_cert_chain(
                certfile=self._client_certificate,
                keyfile=self._client_private_key,
            )
        return context

    def _new_http_client(self) -> httpx.Client:
        return httpx.Client(
            timeout=httpx.Timeout(self.timeout_seconds),
            verify=self._ssl_context(),
            follow_redirects=False,
            trust_env=False,
        )

    def build_resource_client(self, *, timeout_seconds: float) -> httpx.Client:
        """Create a separate upstream client with the same TLS identity and trust."""
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise ValueError("resource_timeout_must_be_positive")
        return httpx.Client(
            timeout=httpx.Timeout(float(timeout_seconds)),
            verify=self._ssl_context(),
            follow_redirects=False,
            trust_env=False,
        )

    def _request_new_token(self) -> tuple[str, float]:
        form = {"grant_type": "client_credentials", "client_id": self.client_id}
        if self.scope:
            form["scope"] = self.scope
        if self.resource:
            # RFC 8707 resource indicator; authorization-server support is required.
            form["resource"] = self.resource
        auth = (
            httpx.BasicAuth(self.client_id, self._client_secret)
            if self.auth_method == "client_secret_basic"
            else None
        )
        try:
            with self._client.stream(
                "POST",
                self.token_url,
                data=form,
                auth=auth,
                headers={"Accept": "application/json"},
            ) as response:
                if response.status_code != 200:
                    raise OAuthTokenError("oauth_token_endpoint_rejected_client_or_request")
                raw = response.read(65_537)
                if len(raw) > 65_536:
                    raise OAuthTokenError("oauth_token_response_too_large")
        except OAuthTokenError:
            raise
        except httpx.RequestError as exc:
            raise OAuthTokenError("oauth_token_endpoint_unavailable") from exc

        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise OAuthTokenError("oauth_token_response_invalid_json") from exc
        if not isinstance(payload, dict):
            raise OAuthTokenError("oauth_token_response_invalid_shape")
        token = payload.get("access_token")
        token_type = payload.get("token_type")
        expires_in = payload.get("expires_in")
        if (
            not isinstance(token, str)
            or not token
            or token.strip() != token
            or any(ch.isspace() for ch in token)
        ):
            raise OAuthTokenError("oauth_access_token_missing_or_invalid")
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise OAuthTokenError("oauth_token_type_must_be_bearer")
        if (
            isinstance(expires_in, bool)
            or not isinstance(expires_in, (int, float))
            or not 0 < expires_in <= 86_400
        ):
            raise OAuthTokenError("oauth_expires_in_must_be_positive_and_at_most_24_hours")
        return token, float(expires_in)

    def get_access_token(self) -> str:
        """Return a still-valid token, refreshing once under concurrent load."""
        while True:
            with self._condition:
                if self._closed:
                    raise OAuthTokenError("oauth_token_provider_closed")
                now = self._clock()
                cached = self._cached
                if cached is not None and now < cached.refresh_at:
                    return cached.value
                if self._refreshing:
                    self._condition.wait()
                    continue
                self._refreshing = True
                previous = cached

            try:
                value, lifetime = self._request_new_token()
                now = self._clock()
                skew = min(self.refresh_skew_seconds, lifetime * 0.1)
                refreshed = _CachedToken(
                    value=value,
                    expires_at=now + lifetime,
                    refresh_at=now + lifetime - skew,
                )
            except OAuthTokenError:
                with self._condition:
                    now = self._clock()
                    self._refreshing = False
                    # A proactive refresh failure does not invalidate an older,
                    # still-unexpired token. An explicitly invalidated token is
                    # cleared before this branch and is never reused.
                    if previous is not None and now < previous.expires_at:
                        retry_at = min(previous.expires_at, now + min(5.0, (previous.expires_at - now) / 2))
                        self._cached = _CachedToken(
                            previous.value,
                            previous.expires_at,
                            retry_at,
                        )
                    self._condition.notify_all()
                    if previous is not None and now < previous.expires_at:
                        return previous.value
                raise
            except Exception as exc:
                with self._condition:
                    self._refreshing = False
                    self._condition.notify_all()
                raise OAuthTokenError("oauth_token_acquisition_failed") from exc

            with self._condition:
                self._cached = refreshed
                self._refreshing = False
                self._condition.notify_all()
                return refreshed.value

    def invalidate(self, token: str) -> None:
        """Forget only the currently cached token, e.g. after an upstream 401."""
        with self._condition:
            if self._cached is not None and self._cached.value == token:
                self._cached = None
            self._condition.notify_all()

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            self._cached = None
            self._condition.notify_all()
        if self._owns_client:
            self._client.close()
