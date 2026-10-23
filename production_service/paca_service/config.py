from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Any
from urllib.parse import urlsplit


class ConfigurationError(RuntimeError):
    """Raised when security-critical configuration is missing or invalid."""


def _required(env: dict[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"Required setting {name} is missing.")
    return value


def _positive_float(env: dict[str, str], name: str, default: str, maximum: float) -> float:
    try:
        value = float(env.get(name, default))
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be numeric.") from exc
    if not (0 < value <= maximum):
        raise ConfigurationError(f"{name} must be greater than zero and at most {maximum}.")
    return value


def _positive_int(env: dict[str, str], name: str, default: str, maximum: int) -> int:
    raw = env.get(name, default)
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer.") from exc
    if not (0 < value <= maximum):
        raise ConfigurationError(f"{name} must be greater than zero and at most {maximum}.")
    return value


def _validate_service_url(name: str, value: str, allow_http: bool) -> str:
    parts = urlsplit(value)
    allowed_schemes = {"https", "http"} if allow_http else {"https"}
    if parts.scheme not in allowed_schemes or not parts.hostname:
        raise ConfigurationError(f"{name} must be an absolute {'HTTP(S)' if allow_http else 'HTTPS'} URL.")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ConfigurationError(f"{name} must not contain credentials, query parameters, or fragments.")
    return value.rstrip("/")


@dataclass(frozen=True)
class Settings:
    database_url: str
    opa_url: str
    opa_decision_path: str
    opa_timeout_seconds: float
    expected_policy_revision: str
    jwt_issuer: str
    jwt_audience: str
    jwt_jwks_url: str
    jwt_timeout_seconds: float
    permit_ttl_seconds: int
    execution_timeout_seconds: float
    stale_execution_seconds: int
    api_base_url: str | None
    api_routes: dict[str, dict[str, Any]]
    api_bearer_token: str | None
    file_root: str | None

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "Settings":
        env = dict(os.environ if environ is None else environ)
        database_url = _required(env, "PACA_DATABASE_URL")
        if not database_url.startswith(("postgresql://", "postgres://")):
            raise ConfigurationError("PACA_DATABASE_URL must use PostgreSQL.")

        opa_url = _validate_service_url(
            "PACA_OPA_URL", _required(env, "PACA_OPA_URL"), allow_http=True
        )
        decision_path = env.get("PACA_OPA_DECISION_PATH", "/v1/data/paca/authz/decision")
        if not decision_path.startswith("/v1/data/") or "?" in decision_path or "#" in decision_path:
            raise ConfigurationError("PACA_OPA_DECISION_PATH must be a fixed OPA Data API path.")

        issuer = _required(env, "PACA_JWT_ISSUER")
        audience = _required(env, "PACA_JWT_AUDIENCE")
        jwks_url = _validate_service_url(
            "PACA_JWT_JWKS_URL", _required(env, "PACA_JWT_JWKS_URL"), allow_http=False
        )
        expected_revision = _required(env, "PACA_EXPECTED_POLICY_REVISION")

        try:
            routes = json.loads(env.get("PACA_API_ROUTES_JSON", "{}"))
        except json.JSONDecodeError as exc:
            raise ConfigurationError("PACA_API_ROUTES_JSON must be valid JSON.") from exc
        if not isinstance(routes, dict) or any(
            not isinstance(action, str) or not isinstance(route, dict)
            for action, route in routes.items()
        ):
            raise ConfigurationError("PACA_API_ROUTES_JSON must map action names to route objects.")

        base = env.get("PACA_API_BASE_URL", "").strip() or None
        if routes and not base:
            raise ConfigurationError("PACA_API_BASE_URL is required when API routes are configured.")
        if base:
            base = _validate_service_url("PACA_API_BASE_URL", base, allow_http=True)

        stale_seconds = _positive_int(env, "PACA_STALE_EXECUTION_SECONDS", "120", 86400)
        execution_timeout = _positive_float(env, "PACA_EXECUTION_TIMEOUT_SECONDS", "10", 120)
        if stale_seconds <= execution_timeout:
            raise ConfigurationError(
                "PACA_STALE_EXECUTION_SECONDS must exceed the upstream execution timeout."
            )

        return cls(
            database_url=database_url,
            opa_url=opa_url,
            opa_decision_path=decision_path,
            opa_timeout_seconds=_positive_float(env, "PACA_OPA_TIMEOUT_SECONDS", "2", 30),
            expected_policy_revision=expected_revision,
            jwt_issuer=issuer,
            jwt_audience=audience,
            jwt_jwks_url=jwks_url,
            jwt_timeout_seconds=_positive_float(env, "PACA_JWT_TIMEOUT_SECONDS", "5", 30),
            permit_ttl_seconds=_positive_int(env, "PACA_PERMIT_TTL_SECONDS", "30", 300),
            execution_timeout_seconds=execution_timeout,
            stale_execution_seconds=stale_seconds,
            api_base_url=base,
            api_routes=routes,
            api_bearer_token=env.get("PACA_API_BEARER_TOKEN", "").strip() or None,
            file_root=env.get("PACA_FILE_ROOT", "").strip() or None,
        )
