from __future__ import annotations

import pytest

from paca_service.config import ConfigurationError, Settings


def base_env(**overrides: str) -> dict[str, str]:
    env = {
        "PACA_DATABASE_URL": "postgresql://paca_runtime:secret@database:5432/paca",
        "PACA_TENANT_CONTEXT_HMAC_KEY": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "PACA_TENANT_CONTEXT_KEY_ID": "v1",
        "PACA_OPA_URL": "http://opa:8181",
        "PACA_EXPECTED_POLICY_REVISION": "paca-dev-2026-10-23",
        "PACA_JWT_ISSUER": "https://identity.example.org/",
        "PACA_JWT_AUDIENCE": "paca-api",
        "PACA_JWT_JWKS_URL": "https://identity.example.org/.well-known/jwks.json",
        "PACA_API_ROUTES_JSON": "{}",
    }
    env.update(overrides)
    return env


def test_compose_internal_database_and_opa_urls_are_accepted():
    settings = Settings.from_env(base_env())
    assert settings.database_url.startswith("postgresql://")
    assert settings.opa_url == "http://opa:8181"


def test_remote_database_requires_full_tls_verification():
    with pytest.raises(ConfigurationError, match="sslmode=verify-full"):
        Settings.from_env(
            base_env(PACA_DATABASE_URL="postgresql://user:password@db.example.org/paca")
        )
    settings = Settings.from_env(
        base_env(
            PACA_DATABASE_URL=(
                "postgresql://user:password@db.example.org/paca?sslmode=verify-full"
            )
        )
    )
    assert "sslmode=verify-full" in settings.database_url


@pytest.mark.parametrize("url", ["http://opa.example.org:8181", "http://policy.internal:8181"])
def test_remote_opa_must_use_https(url: str):
    with pytest.raises(ConfigurationError, match="HTTPS"):
        Settings.from_env(base_env(PACA_OPA_URL=url))


def test_remote_http_api_destination_is_rejected():
    with pytest.raises(ConfigurationError, match="HTTPS"):
        Settings.from_env(
            base_env(PACA_API_BASE_URL="http://api.example.org")
        )


def test_loopback_http_api_destination_is_allowed_for_local_testing():
    settings = Settings.from_env(base_env(PACA_API_BASE_URL="http://127.0.0.1:9010"))
    assert settings.api_base_url == "http://127.0.0.1:9010"


def test_non_https_oidc_issuer_is_rejected():
    with pytest.raises(ConfigurationError, match="HTTPS"):
        Settings.from_env(base_env(PACA_JWT_ISSUER="http://identity.example.org/"))


def test_tenant_context_key_must_be_256_bit_hex():
    with pytest.raises(ConfigurationError, match="64 hexadecimal"):
        Settings.from_env(base_env(PACA_TENANT_CONTEXT_HMAC_KEY="too-short"))


def test_tenant_context_key_id_is_strictly_validated():
    with pytest.raises(ConfigurationError, match="KEY_ID"):
        Settings.from_env(base_env(PACA_TENANT_CONTEXT_KEY_ID="bad key id"))


def test_access_token_purpose_claim_is_configurable_and_defaults_to_access():
    settings = Settings.from_env(base_env())
    assert settings.jwt_token_use_claim == "token_use"
    assert settings.jwt_expected_token_use == "access"

    custom = Settings.from_env(
        base_env(
            PACA_JWT_TOKEN_USE_CLAIM="paca_token_type",
            PACA_JWT_EXPECTED_TOKEN_USE="api_access",
        )
    )
    assert custom.jwt_token_use_claim == "paca_token_type"
    assert custom.jwt_expected_token_use == "api_access"


@pytest.mark.parametrize(
    "overrides",
    [
        {"PACA_JWT_TOKEN_USE_CLAIM": ""},
        {"PACA_JWT_TOKEN_USE_CLAIM": "bad claim name"},
        {"PACA_JWT_EXPECTED_TOKEN_USE": ""},
    ],
)
def test_invalid_access_token_purpose_configuration_is_rejected(overrides):
    with pytest.raises(ConfigurationError, match="TOKEN_USE"):
        Settings.from_env(base_env(**overrides))


def test_remote_opa_requires_bearer_credential():
    with pytest.raises(ConfigurationError, match="PACA_OPA_BEARER_TOKEN"):
        Settings.from_env(base_env(PACA_OPA_URL="https://opa.example.org:8181"))
    settings = Settings.from_env(
        base_env(
            PACA_OPA_URL="https://opa.example.org:8181",
            PACA_OPA_BEARER_TOKEN="opa-service-token",
        )
    )
    assert settings.opa_bearer_token == "opa-service-token"


@pytest.mark.parametrize("token", ["has spaces", "bad\ntoken"])
def test_opa_bearer_credential_rejects_whitespace(token: str):
    with pytest.raises(ConfigurationError, match="PACA_OPA_BEARER_TOKEN"):
        Settings.from_env(base_env(PACA_OPA_BEARER_TOKEN=token))


def test_remote_downstream_routes_require_a_service_credential():
    routes = '{"document.update":{"method":"PATCH","path":"/v1/documents/{resource_id}","args_mode":"json"}}'
    with pytest.raises(ConfigurationError, match="PACA_API_BEARER_TOKEN"):
        Settings.from_env(
            base_env(
                PACA_API_BASE_URL="https://api.example.org",
                PACA_API_ROUTES_JSON=routes,
            )
        )
    settings = Settings.from_env(
        base_env(
            PACA_API_BASE_URL="https://api.example.org",
            PACA_API_ROUTES_JSON=routes,
            PACA_API_BEARER_TOKEN="downstream-service-token",
        )
    )
    assert settings.api_bearer_token == "downstream-service-token"


def test_loopback_downstream_route_can_use_local_development_without_service_token():
    routes = '{"document.update":{"method":"PATCH","path":"/v1/documents/{resource_id}","args_mode":"json"}}'
    settings = Settings.from_env(
        base_env(
            PACA_API_BASE_URL="http://127.0.0.1:9010",
            PACA_API_ROUTES_JSON=routes,
        )
    )
    assert settings.api_base_url == "http://127.0.0.1:9010"
    assert settings.api_bearer_token is None



def test_remote_opa_accepts_oauth_client_credentials_instead_of_static_token():
    settings = Settings.from_env(
        base_env(
            PACA_OPA_URL="https://opa.example.org:8181",
            PACA_OPA_OAUTH_TOKEN_URL="https://identity.example.org/oauth/token",
            PACA_OPA_OAUTH_CLIENT_ID="paca-opa-client",
            PACA_OPA_OAUTH_CLIENT_SECRET="opa-secret",
            PACA_OPA_OAUTH_SCOPE="opa.decide",
        )
    )
    assert settings.opa_bearer_token is None
    assert settings.opa_oauth_token_url == "https://identity.example.org/oauth/token"
    assert settings.opa_oauth_client_id == "paca-opa-client"
    assert settings.opa_oauth_client_secret == "opa-secret"
    assert settings.opa_oauth_scope == "opa.decide"


def test_remote_downstream_route_accepts_independent_oauth_client_credentials():
    routes = '{"document.update":{"method":"PATCH","path":"/v1/documents/{resource_id}","args_mode":"json"}}'
    settings = Settings.from_env(
        base_env(
            PACA_API_BASE_URL="https://api.example.org",
            PACA_API_ROUTES_JSON=routes,
            PACA_API_OAUTH_TOKEN_URL="https://identity.example.org/oauth/token",
            PACA_API_OAUTH_CLIENT_ID="paca-api-client",
            PACA_API_OAUTH_CLIENT_SECRET="api-secret",
            PACA_API_OAUTH_SCOPE="documents.write",
        )
    )
    assert settings.api_bearer_token is None
    assert settings.api_oauth_token_url == "https://identity.example.org/oauth/token"
    assert settings.api_oauth_client_id == "paca-api-client"
    assert settings.api_oauth_client_secret == "api-secret"
    assert settings.api_oauth_scope == "documents.write"


@pytest.mark.parametrize(
    "overrides",
    [
        {"PACA_OPA_OAUTH_TOKEN_URL": "https://identity.example.org/token"},
        {"PACA_OPA_OAUTH_CLIENT_ID": "paca-client"},
        {"PACA_OPA_OAUTH_CLIENT_SECRET": "secret"},
    ],
)
def test_partial_opa_oauth_configuration_is_rejected(overrides):
    with pytest.raises(ConfigurationError, match="must be configured together"):
        Settings.from_env(
            base_env(
                PACA_OPA_URL="https://opa.example.org",
                **overrides,
            )
        )


def test_static_opa_token_and_oauth_credentials_cannot_be_combined():
    with pytest.raises(ConfigurationError, match="mutually exclusive"):
        Settings.from_env(
            base_env(
                PACA_OPA_URL="https://opa.example.org",
                PACA_OPA_BEARER_TOKEN="static-token",
                PACA_OPA_OAUTH_TOKEN_URL="https://identity.example.org/token",
                PACA_OPA_OAUTH_CLIENT_ID="paca-opa",
                PACA_OPA_OAUTH_CLIENT_SECRET="secret",
            )
        )


def test_remote_oauth_token_endpoint_requires_https():
    with pytest.raises(ConfigurationError, match="HTTPS"):
        Settings.from_env(
            base_env(
                PACA_OPA_URL="https://opa.example.org",
                PACA_OPA_OAUTH_TOKEN_URL="http://identity.example.org/token",
                PACA_OPA_OAUTH_CLIENT_ID="paca-opa",
                PACA_OPA_OAUTH_CLIENT_SECRET="secret",
            )
        )


def test_api_oauth_settings_require_configured_downstream_routes():
    with pytest.raises(ConfigurationError, match="require PACA_API_BASE_URL"):
        Settings.from_env(
            base_env(
                PACA_API_OAUTH_TOKEN_URL="https://identity.example.org/token",
                PACA_API_OAUTH_CLIENT_ID="paca-api",
                PACA_API_OAUTH_CLIENT_SECRET="secret",
            )
        )
