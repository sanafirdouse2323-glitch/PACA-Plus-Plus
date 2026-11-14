from __future__ import annotations

import base64
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

import httpx
import pytest

from paca_service.service_tokens import (
    ClientCredentialsTokenProvider,
    TokenProviderUnavailable,
)


def token_response(token: str, expires_in: int = 120) -> httpx.Response:
    return httpx.Response(
        200,
        json={"access_token": token, "token_type": "Bearer", "expires_in": expires_in},
    )


def make_provider(handler, *, clock=lambda: 100.0, client=None, skew=30):
    http = client or httpx.Client(transport=httpx.MockTransport(handler))
    return ClientCredentialsTokenProvider(
        "https://identity.example.org/oauth2/token",
        "paca-service-client",
        "test-client-secret",
        scope="opa.decide service.execute",
        client=http,
        clock=clock,
        refresh_skew_seconds=skew,
    )


def test_client_credentials_uses_basic_auth_and_caches_token_until_refresh_window():
    observed = []
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        observed.append(request)
        return token_response("opaque-token-1")

    provider = make_provider(handler)
    try:
        assert provider.get_token() == "opaque-token-1"
        assert provider.get_token() == "opaque-token-1"
        assert calls == 1
        request = observed[0]
        expected = base64.b64encode(
            b"paca-service-client:test-client-secret"
        ).decode("ascii")
        assert request.headers["Authorization"] == f"Basic {expected}"
        assert request.headers["Content-Type"].startswith(
            "application/x-www-form-urlencoded"
        )
        assert dict(httpx.QueryParams(request.content.decode())) == {
            "grant_type": "client_credentials",
            "scope": "opa.decide service.execute",
        }
    finally:
        provider.close()


def test_client_credentials_refreshes_before_expiry_and_replaces_cached_token():
    now = [100.0]
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return token_response(f"token-{calls}", expires_in=100)

    provider = make_provider(handler, clock=lambda: now[0], skew=20)
    try:
        assert provider.get_token() == "token-1"
        now[0] = 181.0
        assert provider.get_token() == "token-2"
        assert provider.get_token() == "token-2"
        assert calls == 2
    finally:
        provider.close()


def test_concurrent_callers_share_one_token_refresh():
    calls = 0
    call_lock = Lock()

    def handler(request):
        nonlocal calls
        with call_lock:
            calls += 1
        return token_response("one-shared-token")

    provider = make_provider(handler)
    try:
        with ThreadPoolExecutor(max_workers=12) as pool:
            tokens = list(pool.map(lambda _index: provider.get_token(), range(48)))
        assert set(tokens) == {"one-shared-token"}
        assert calls == 1
    finally:
        provider.close()


def test_failed_proactive_refresh_reuses_only_a_still_valid_token():
    now = [100.0]
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return token_response("still-valid", expires_in=100)
        return httpx.Response(503, json={"error": "temporarily_unavailable"})

    provider = make_provider(handler, clock=lambda: now[0], skew=20)
    try:
        assert provider.get_token() == "still-valid"
        now[0] = 181.0
        assert provider.get_token() == "still-valid"
        assert calls == 2
        now[0] = 201.0
        with pytest.raises(TokenProviderUnavailable, match="oauth_token_endpoint_rejected_request"):
            provider.get_token()
    finally:
        provider.close()


@pytest.mark.parametrize(
    "payload",
    [
        {"access_token": "token", "token_type": "MAC", "expires_in": 60},
        {"access_token": "token", "token_type": "Bearer", "expires_in": 0},
        {"access_token": "token", "token_type": "Bearer", "expires_in": True},
        {"access_token": "token", "token_type": "Bearer", "expires_in": 86_401},
        {"access_token": "bad token", "token_type": "Bearer", "expires_in": 60},
        {"access_token": "", "token_type": "Bearer", "expires_in": 60},
    ],
)
def test_invalid_oauth_token_responses_are_rejected(payload):
    provider = make_provider(lambda request: httpx.Response(200, json=payload))
    try:
        with pytest.raises(TokenProviderUnavailable):
            provider.get_token()
    finally:
        provider.close()


def test_oversized_oauth_token_response_is_rejected():
    body = json.dumps(
        {
            "access_token": "x" * 200,
            "token_type": "Bearer",
            "expires_in": 60,
            "extra": "y" * 1000,
        }
    ).encode()
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=body)
        )
    )
    provider = ClientCredentialsTokenProvider(
        "https://identity.example.org/token",
        "client",
        "secret",
        client=client,
        max_response_bytes=128,
    )
    try:
        with pytest.raises(TokenProviderUnavailable, match="oauth_token_response_too_large"):
            provider.get_token()
    finally:
        provider.close()


def test_redirecting_token_endpoint_client_is_rejected():
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                302, headers={"Location": "https://attacker.example/collect"}
            )
        ),
        follow_redirects=True,
    )
    with pytest.raises(ValueError, match="disable_redirects"):
        ClientCredentialsTokenProvider(
            "https://identity.example.org/token",
            "client",
            "secret",
            client=client,
        )
    client.close()


def test_http_token_endpoint_is_allowed_only_for_loopback_test_services():
    provider = ClientCredentialsTokenProvider(
        "http://127.0.0.1:9001/token",
        "client",
        "secret",
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: token_response("local-token")
            )
        ),
    )
    try:
        assert provider.get_token() == "local-token"
    finally:
        provider.close()

    with pytest.raises(ValueError, match="requires_https"):
        ClientCredentialsTokenProvider(
            "http://identity.example.org/token",
            "client",
            "secret",
        )
