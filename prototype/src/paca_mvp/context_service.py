"""Reference trusted authorization-context service for PACA++.

This service is a read-only authorization-context reference implementation.
It maps a verified (issuer, subject, audience) tuple to an administrator-
provisioned internal principal, then resolves current role/capability/suspension
and resource ownership from PostgreSQL. It does not accept policy attributes
from the caller, and deliberately has no mutation/admin endpoints.

The production deployment must place this service on a private network, protect
its service credential, and grant its database role read-only access to the
paca_context_* tables.
"""
from __future__ import annotations

import hmac
import os
from typing import Any, Protocol
from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .hardening import _validate_identifier


class ContextRepositoryUnavailable(RuntimeError):
    """The trusted authorization database could not be queried."""


class AuthorizationContextRepository(Protocol):
    def get_context(self, subject: str, issuer: str, audience: str,
                    action: str, resource: str) -> dict[str, Any]:
        """Resolve current authorization facts from administrator-managed data."""
    def ping(self) -> None:
        """Raise if the repository cannot answer a readiness check."""


class PostgresAuthorizationContextRepository:
    """Resolve context from the tables created by migration 002.

    A principal identity is keyed by issuer, subject, audience, and tenant.
    Tenant is derived from the administrator-registered resource, never from
    the request body. Resource ownership uses internal principal IDs, not raw
    OpenID Connect subjects.
    """
    def __init__(self, dsn: str, connect_timeout: int = 5):
        if not isinstance(dsn, str) or not dsn.startswith(("postgresql://", "postgres://")):
            raise ValueError("dsn must be a PostgreSQL connection URL")
        parsed = urlparse(dsn)
        if not parsed.hostname:
            raise ValueError("PostgreSQL DSN must include a hostname")
        if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            sslmode = parse_qs(parsed.query).get("sslmode", [""])[-1]
            if sslmode != "verify-full":
                raise ValueError("non-loopback PostgreSQL DSNs must set sslmode=verify-full")
        if connect_timeout < 1 or connect_timeout > 120:
            raise ValueError("connect_timeout must be between 1 and 120 seconds")
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError(
                "PostgresAuthorizationContextRepository requires psycopg 3"
            ) from exc
        self.dsn = dsn
        self.connect_timeout = connect_timeout
        self._psycopg = psycopg
        self._dict_row = dict_row

    def ping(self) -> None:
        try:
            with self._psycopg.connect(
                self.dsn, connect_timeout=self.connect_timeout, row_factory=self._dict_row
            ) as db:
                db.execute("SELECT 1").fetchone()
        except Exception as exc:
            raise ContextRepositoryUnavailable("context database is unavailable") from exc

    def get_context(self, subject: str, issuer: str, audience: str,
                    action: str, resource: str) -> dict[str, Any]:
        for value, name in (
            (subject, "subject"), (issuer, "issuer"), (audience, "audience"),
            (action, "action"), (resource, "resource"),
        ):
            _validate_identifier(value, name)
        try:
            with self._psycopg.connect(
                self.dsn, connect_timeout=self.connect_timeout, row_factory=self._dict_row
            ) as db:
                target = db.execute(
                    """SELECT tenant_id, owner_principal_id
                       FROM paca_context_resources WHERE resource = %s""",
                    (resource,),
                ).fetchone()
                if target is None:
                    return {
                        "authorization": {
                            "principal_id": None, "tenant_id": None, "role": "none",
                            "can_create_tickets": False, "suspended": True,
                        },
                        "resource": {"tenant_id": None, "owner_principal_id": None},
                    }

                principal = db.execute(
                    """SELECT principal_id, tenant_id, role, can_create_tickets,
                              suspended, active
                       FROM paca_context_principals
                       WHERE issuer = %s AND subject = %s AND audience = %s
                         AND tenant_id = %s""",
                    (issuer, subject, audience, target["tenant_id"]),
                ).fetchone()

                # Missing or inactive identities resolve to a deny-only context,
                # rather than a permissive default or a caller-visible data leak.
                if principal is None or not principal["active"]:
                    authorization = {
                        "principal_id": None,
                        "tenant_id": target["tenant_id"],
                        "role": "none",
                        "can_create_tickets": False,
                        "suspended": True,
                    }
                else:
                    authorization = {
                        "principal_id": principal["principal_id"],
                        "tenant_id": principal["tenant_id"],
                        "role": principal["role"],
                        "can_create_tickets": bool(principal["can_create_tickets"]),
                        "suspended": bool(principal["suspended"]),
                    }
                return {
                    "authorization": authorization,
                    "resource": {
                        "tenant_id": target["tenant_id"],
                        "owner_principal_id": target["owner_principal_id"],
                    },
                }
        except ContextRepositoryUnavailable:
            raise
        except Exception as exc:
            raise ContextRepositoryUnavailable("context database query failed") from exc


class ContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(min_length=1, max_length=512)
    issuer: str = Field(min_length=1, max_length=2048)
    audience: str = Field(min_length=1, max_length=512)
    action: str = Field(min_length=1, max_length=512)
    resource: str = Field(min_length=1, max_length=512)


def create_context_app(
    repository: AuthorizationContextRepository | None = None,
    service_token: str | None = None,
) -> FastAPI:
    """Build the private context API; credentials and DB DSN never have defaults."""
    token = service_token if service_token is not None else os.environ.get(
        "PACA_CONTEXT_SERVICE_TOKEN", ""
    )
    if (not isinstance(token, str) or len(token) < 16 or not token.isascii()
            or token.strip() != token or any(ch.isspace() for ch in token)):
        raise RuntimeError(
            "PACA_CONTEXT_SERVICE_TOKEN must be an ASCII secret of at least 16 characters"
        )
    if repository is None:
        dsn = os.environ.get("PACA_CONTEXT_DATABASE_URL", "").strip()
        if not dsn:
            raise RuntimeError("PACA_CONTEXT_DATABASE_URL is not configured")
        repository = PostgresAuthorizationContextRepository(dsn)

    app = FastAPI(
        title="PACA++ Trusted Authorization Context",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.context_repository = repository

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> dict[str, str]:
        try:
            repository.ping()
        except Exception as exc:
            raise HTTPException(status_code=503, detail="context service is not ready") from exc
        return {"status": "ready"}

    @app.post("/v1/attributes")
    def attributes(payload: ContextRequest, request: Request) -> dict[str, Any]:
        # Inspect raw ASGI headers before trusting a framework-selected value.
        auth_values = [
            value for name, value in request.scope.get("headers", [])
            if name.lower() == b"authorization"
        ]
        if len(auth_values) != 1:
            raise HTTPException(status_code=400, detail="exactly one Authorization header is required")
        try:
            authorization = auth_values[0].decode("ascii")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=401, detail="invalid service credential") from exc
        parts = authorization.split()
        if (len(parts) != 2 or parts[0].lower() != "bearer"
                or not hmac.compare_digest(parts[1], token)):
            raise HTTPException(
                status_code=401, detail="service authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            return repository.get_context(
                subject=payload.subject,
                issuer=payload.issuer,
                audience=payload.audience,
                action=payload.action,
                resource=payload.resource,
            )
        except ContextRepositoryUnavailable as exc:
            raise HTTPException(status_code=503, detail="trusted context unavailable") from exc

    return app
