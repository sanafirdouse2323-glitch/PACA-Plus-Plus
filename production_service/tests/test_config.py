from __future__ import annotations

import pytest

from paca_service.config import ConfigurationError, Settings


def base_env(**overrides: str) -> dict[str, str]:
    env = {
        "PACA_DATABASE_URL": "postgresql://paca_runtime:secret@database:5432/paca",
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
