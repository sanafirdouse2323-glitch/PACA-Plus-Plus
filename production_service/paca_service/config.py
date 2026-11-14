from __future__ import annotations

import hmac
import json
import os
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlsplit


class ConfigurationError(RuntimeError):
    """Raised when security-critical configuration is missing or invalid."""


_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


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


def _validate_database_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in {"postgresql", "postgres"} or not parts.hostname:
        raise ConfigurationError("PACA_DATABASE_URL must be an absolute PostgreSQL URL.")
    host = parts.hostname.lower().rstrip(".")
    # The supplied Compose stack intentionally uses private Docker-network traffic.
    # Any other remote database must authenticate its TLS peer, not merely encrypt.
    if host not in _LOOPBACK_HOSTS | {"database"}:
        sslmodes = parse_qs(parts.query, keep_blank_values=True).get("sslmode", [])
        if sslmodes != ["verify-full"]:
            raise ConfigurationError(
                "Remote PACA_DATABASE_URL must set sslmode=verify-full."
            )
    return value


def _validate_service_url(
    name: str,
    value: str,
    allow_http: bool,
    http_host_allowlist: frozenset[str] = frozenset(),
) -> str:
    parts = urlsplit(value)
    allowed_schemes = {"https", "http"} if allow_http else {"https"}
    if parts.scheme not in allowed_schemes or not parts.hostname:
        raise ConfigurationError(
            f"{name} must be an absolute {'HTTP(S)' if allow_http else 'HTTPS'} URL."
        )
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ConfigurationError(f"{name} must not contain credentials, query parameters, or fragments.")
    if parts.scheme == "http":
        host = parts.hostname.lower().rstrip(".")
        if host not in _LOOPBACK_HOSTS | http_host_allowlist:
            raise ConfigurationError(f"{name} must use HTTPS for non-local hosts.")
    return value.rstrip("/")



def _oauth_client_configuration(
    env: dict[str, str],
    prefix: str,
    *,
    static_token: str | None,
) -> tuple[str | None, str | None, str | None, str | None]:
    token_url_name = f"{prefix}_OAUTH_TOKEN_URL"
    client_id_name = f"{prefix}_OAUTH_CLIENT_ID"
    client_secret_name = f"{prefix}_OAUTH_CLIENT_SECRET"
    scope_name = f"{prefix}_OAUTH_SCOPE"
    raw_url = env.get(token_url_name, "").strip()
    raw_client_id = env.get(client_id_name, "")
    raw_client_secret = env.get(client_secret_name, "")
    raw_scope = env.get(scope_name, "")
    configured = any((raw_url, raw_client_id, raw_client_secret, raw_scope))
    if not configured:
        return None, None, None, None
    if static_token:
        raise ConfigurationError(
            f"{prefix}_BEARER_TOKEN and {prefix}_OAUTH_* settings are mutually exclusive."
        )
    if not raw_url or not raw_client_id or not raw_client_secret:
        raise ConfigurationError(
            f"{token_url_name}, {client_id_name}, and {client_secret_name} must be configured together."
        )
    token_url = _validate_service_url(
        token_url_name, raw_url, allow_http=True
    )
    if (
        raw_client_id.strip() != raw_client_id
        or any(ch.isspace() for ch in raw_client_id)
        or any(ch in raw_client_id for ch in "\r\n")
    ):
        raise ConfigurationError(f"{client_id_name} must be a non-whitespace identifier.")
    if any(ch in raw_client_secret for ch in "\r\n"):
        raise ConfigurationError(f"{client_secret_name} must not contain CR or LF.")
    if raw_scope and (
        raw_scope.strip() != raw_scope
        or any(ch in raw_scope for ch in "\r\n\t")
        or len(raw_scope) > 1024
    ):
        raise ConfigurationError(f"{scope_name} is invalid.")
    return token_url, raw_client_id, raw_client_secret, raw_scope or None


@dataclass(frozen=True)
class Settings:
    database_url: str
    tenant_context_hmac_key: bytes
    tenant_context_key_id: str
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
    api_base_url: str | None
    api_routes: dict[str, dict[str, Any]]
    api_bearer_token: str | None
    file_root: str | None
    jwt_token_use_claim: str = "token_use"
    jwt_expected_token_use: str = "access"
    opa_bearer_token: str | None = None
    opa_oauth_token_url: str | None = None
    opa_oauth_client_id: str | None = None
    opa_oauth_client_secret: str | None = None
    opa_oauth_scope: str | None = None
    api_oauth_token_url: str | None = None
    api_oauth_client_id: str | None = None
    api_oauth_client_secret: str | None = None
    api_oauth_scope: str | None = None

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> Settings:
        env = dict(os.environ if environ is None else environ)
        database_url = _validate_database_url(_required(env, "PACA_DATABASE_URL"))
        raw_context_key = _required(env, "PACA_TENANT_CONTEXT_HMAC_KEY")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", raw_context_key):
            raise ConfigurationError(
                "PACA_TENANT_CONTEXT_HMAC_KEY must be exactly 64 hexadecimal characters (32 bytes)."
            )
        context_key_id = env.get("PACA_TENANT_CONTEXT_KEY_ID", "v1").strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", context_key_id):
            raise ConfigurationError(
                "PACA_TENANT_CONTEXT_KEY_ID must be 1-32 safe identifier characters."
            )

        opa_url = _validate_service_url(
            "PACA_OPA_URL",
            _required(env, "PACA_OPA_URL"),
            allow_http=True,
            http_host_allowlist=frozenset({"opa"}),
        )
        decision_path = env.get("PACA_OPA_DECISION_PATH", "/v1/data/paca/authz/decision")
        if not decision_path.startswith("/v1/data/") or "?" in decision_path or "#" in decision_path:
            raise ConfigurationError("PACA_OPA_DECISION_PATH must be a fixed OPA Data API path.")
        raw_opa_bearer_token = env.get("PACA_OPA_BEARER_TOKEN", "")
        opa_bearer_token = raw_opa_bearer_token or None
        if opa_bearer_token and (
            opa_bearer_token.strip() != opa_bearer_token
            or any(ch.isspace() for ch in opa_bearer_token)
        ):
            raise ConfigurationError("PACA_OPA_BEARER_TOKEN must be a non-whitespace token.")
        (
            opa_oauth_token_url,
            opa_oauth_client_id,
            opa_oauth_client_secret,
            opa_oauth_scope,
        ) = _oauth_client_configuration(
            env, "PACA_OPA", static_token=opa_bearer_token
        )
        opa_host = urlsplit(opa_url).hostname.lower().rstrip(".")
        if (
            opa_host not in _LOOPBACK_HOSTS | {"opa"}
            and not opa_bearer_token
            and opa_oauth_token_url is None
        ):
            raise ConfigurationError(
                "Remote OPA requires PACA_OPA_BEARER_TOKEN or the PACA_OPA_OAUTH_* client-credentials settings."
            )

        issuer = _required(env, "PACA_JWT_ISSUER")
        issuer_parts = urlsplit(issuer)
        if (
            issuer_parts.scheme != "https"
            or not issuer_parts.hostname
            or issuer_parts.username
            or issuer_parts.password
            or issuer_parts.query
            or issuer_parts.fragment
        ):
            raise ConfigurationError("PACA_JWT_ISSUER must be an absolute HTTPS URL without credentials/query/fragment.")
        audience = _required(env, "PACA_JWT_AUDIENCE")
        token_use_claim = env.get("PACA_JWT_TOKEN_USE_CLAIM", "token_use").strip()
        expected_token_use = env.get("PACA_JWT_EXPECTED_TOKEN_USE", "access").strip()
        if (
            not token_use_claim
            or not token_use_claim.replace("_", "").isalnum()
            or not expected_token_use
        ):
            raise ConfigurationError(
                "PACA_JWT_TOKEN_USE_CLAIM and PACA_JWT_EXPECTED_TOKEN_USE must be non-empty safe values."
            )
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
        api_bearer_token = env.get("PACA_API_BEARER_TOKEN", "")
        if api_bearer_token and (
            api_bearer_token.strip() != api_bearer_token
            or any(ch.isspace() for ch in api_bearer_token)
        ):
            raise ConfigurationError("PACA_API_BEARER_TOKEN must be a non-whitespace token.")
        api_bearer_token = api_bearer_token or None
        (
            api_oauth_token_url,
            api_oauth_client_id,
            api_oauth_client_secret,
            api_oauth_scope,
        ) = _oauth_client_configuration(
            env, "PACA_API", static_token=api_bearer_token
        )
        if (api_oauth_token_url is not None) and not (base and routes):
            raise ConfigurationError(
                "PACA_API_OAUTH_* settings require PACA_API_BASE_URL and configured API routes."
            )
        if base and routes:
            api_host = urlsplit(base).hostname.lower().rstrip(".")
            if (
                api_host not in _LOOPBACK_HOSTS
                and not api_bearer_token
                and api_oauth_token_url is None
            ):
                raise ConfigurationError(
                    "Remote downstream API routes require PACA_API_BEARER_TOKEN or PACA_API_OAUTH_* client-credentials settings."
                )

        # OPA and downstream APIs are separate service identities. Refuse
        # accidental credential reuse rather than relying only on documentation.
        if opa_oauth_client_id and api_oauth_client_id:
            if opa_oauth_client_id == api_oauth_client_id:
                raise ConfigurationError(
                    "OPA and downstream API OAuth clients must use different client IDs."
                )
            if hmac.compare_digest(
                opa_oauth_client_secret.encode("utf-8"),
                api_oauth_client_secret.encode("utf-8"),
            ):
                raise ConfigurationError(
                    "OPA and downstream API OAuth clients must use different client secrets."
                )
        if opa_bearer_token and api_bearer_token and hmac.compare_digest(
            opa_bearer_token.encode("utf-8"),
            api_bearer_token.encode("utf-8"),
        ):
            raise ConfigurationError(
                "OPA and downstream API static bearer tokens must be different."
            )

        execution_timeout = _positive_float(env, "PACA_EXECUTION_TIMEOUT_SECONDS", "10", 120)

        return cls(
            database_url=database_url,
            tenant_context_hmac_key=bytes.fromhex(raw_context_key),
            tenant_context_key_id=context_key_id,
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
            api_base_url=base,
            api_routes=routes,
            api_bearer_token=api_bearer_token,
            file_root=env.get("PACA_FILE_ROOT", "").strip() or None,
            jwt_token_use_claim=token_use_claim,
            jwt_expected_token_use=expected_token_use,
            opa_bearer_token=opa_bearer_token,
            opa_oauth_token_url=opa_oauth_token_url,
            opa_oauth_client_id=opa_oauth_client_id,
            opa_oauth_client_secret=opa_oauth_client_secret,
            opa_oauth_scope=opa_oauth_scope,
            api_oauth_token_url=api_oauth_token_url,
            api_oauth_client_id=api_oauth_client_id,
            api_oauth_client_secret=api_oauth_client_secret,
            api_oauth_scope=api_oauth_scope,
        )
