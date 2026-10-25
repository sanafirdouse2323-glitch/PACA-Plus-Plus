"""Runnable, fail-closed ASGI gateway for a configured ticket-create protected tool.

The API intentionally exposes one action/resource pair rather than accepting
arbitrary tool names or URLs from the caller. OIDC, trusted context, OPA,
database and downstream API endpoints are deployment configuration.

Run with:
    uvicorn paca_mvp.service:create_app --factory --host 127.0.0.1 --port 8080

For production, terminate TLS at a trusted proxy/load balancer and protect that
hop, configure trusted proxy handling explicitly, and run with least privilege.
"""
from __future__ import annotations

import json
import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .hardening import (
    AuthenticationFailed, ContextUnavailable, EffectOutcomeUnknown,
    GuardedGateway, IdempotencyConflict, IdentityProviderUnavailable, OPAClient, PermitRejected,
    PolicyUnavailable, SQLitePermitStore,
)
from .postgres import PostgresPermitStore
from .providers import (
    HTTPAuthorizationContextProvider, HTTPJSONToolAdapter, HTTPRoute,
    OIDCJWTIdentityProvider,
)


MAX_REQUEST_BYTES = 64 * 1024
TICKET_ACTION = "ticket.create"
TICKET_RESOURCE = "ticket-collection:default"
TICKET_PATH = "/v1/tickets"


class TicketCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    title: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)


class RequestSizeLimitMiddleware:
    """Bound request bodies before JSON validation, including chunked bodies."""
    def __init__(self, app: ASGIApp, max_bytes: int = MAX_REQUEST_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        raw_length = headers.get(b"content-length")
        if raw_length is not None:
            try:
                content_length = int(raw_length)
            except ValueError:
                await self._respond(send, 400, {"detail": "invalid Content-Length"})
                return
            if content_length < 0:
                await self._respond(send, 400, {"detail": "invalid Content-Length"})
                return
            if content_length > self.max_bytes:
                await self._respond(send, 413, {"detail": "request body too large"})
                return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            body.extend(message.get("body", b""))
            if len(body) > self.max_bytes:
                await self._respond(send, 413, {"detail": "request body too large"})
                return
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay_receive() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _respond(send: Send, status: int, payload: dict[str, str]) -> None:
        raw = json.dumps(payload, separators=(",", ":")).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(raw)).encode())]})
        await send({"type": "http.response.body", "body": raw})


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"required environment variable {name} is not configured")
    return value


def build_gateway_from_environment():
    """Create production-configured providers from environment; never invent credentials."""
    identity = OIDCJWTIdentityProvider(
        issuer=_required_env("OIDC_ISSUER"),
        audience=_required_env("OIDC_AUDIENCE"),
        jwks_url=_required_env("OIDC_JWKS_URL"),
    )
    context = HTTPAuthorizationContextProvider(
        endpoint=_required_env("PACA_CONTEXT_URL"),
        service_token=_required_env("PACA_CONTEXT_SERVICE_TOKEN"),
    )
    opa = OPAClient(
        base_url=_required_env("OPA_URL"),
        bearer_token=os.environ.get("OPA_BEARER_TOKEN") or None,
    )
    database_url = os.environ.get("PACA_DATABASE_URL", "").strip()
    if database_url:
        auto_migrate_value = os.environ.get("PACA_DATABASE_AUTO_MIGRATE", "false").strip().lower()
        if auto_migrate_value not in {"true", "false", "1", "0", "yes", "no"}:
            raise RuntimeError("PACA_DATABASE_AUTO_MIGRATE must be true/false, 1/0, or yes/no")
        auto_migrate = auto_migrate_value in {"true", "1", "yes"}
        store = PostgresPermitStore(database_url, initialize_schema=auto_migrate)
    else:
        store = SQLitePermitStore(_required_env("PACA_SQLITE_PATH"))

    downstream_url = _required_env("PACA_PROTECTED_API_BASE_URL")
    downstream_token = _required_env("PACA_PROTECTED_API_TOKEN")
    downstream_path = os.environ.get("PACA_TICKET_CREATE_PATH", TICKET_PATH).strip()
    adapter = HTTPJSONToolAdapter(
        base_url=downstream_url,
        routes={(TICKET_ACTION, TICKET_RESOURCE): HTTPRoute("POST", downstream_path)},
        bearer_token=downstream_token,
        timeout_seconds=5.0,
        max_response_bytes=MAX_REQUEST_BYTES,
    )
    return GuardedGateway(opa, store, identity, context), adapter, store, opa


def create_app(
    gateway: GuardedGateway | None = None,
    ticket_adapter: Any | None = None,
    store: Any | None = None,
    opa: Any | None = None,
) -> FastAPI:
    """Build the ASGI app. Tests may inject explicit doubles; runtime defaults to env config."""
    if gateway is None:
        gateway, ticket_adapter, store, opa = build_gateway_from_environment()
    elif ticket_adapter is None or store is None or opa is None:
        raise ValueError("when injecting a gateway, ticket_adapter, store, and opa must also be supplied")

    app = FastAPI(
        title="PACA++ Guarded Tool Gateway",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=MAX_REQUEST_BYTES)
    app.state.gateway = gateway
    app.state.ticket_adapter = ticket_adapter
    app.state.store = store
    app.state.opa = opa

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> dict[str, Any]:
        try:
            version = opa.get_policy_version()
            state_version = store.current_state_version()
        except Exception as exc:
            raise HTTPException(status_code=503, detail="authorization dependencies are not ready") from exc
        return {"status": "ready", "policy_version": version, "state_version": state_version}

    @app.post("/v1/tickets")
    def create_ticket(
        payload: TicketCreate,
        authorization: str | None = Header(default=None, alias="Authorization"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> Any:
        if not authorization:
            raise HTTPException(status_code=401, detail="Bearer token required",
                                headers={"WWW-Authenticate": "Bearer"})
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(status_code=401, detail="invalid bearer authorization header",
                                headers={"WWW-Authenticate": "Bearer"})
        if not idempotency_key:
            raise HTTPException(status_code=400, detail="Idempotency-Key header required")
        if (len(idempotency_key) > 512 or not idempotency_key.strip()
                or any(ord(ch) < 32 for ch in idempotency_key)):
            raise HTTPException(status_code=400, detail="invalid Idempotency-Key header")

        try:
            return gateway.authorize_and_execute(
                credential=parts[1],
                action=TICKET_ACTION,
                resource=TICKET_RESOURCE,
                arguments=payload.model_dump(exclude_none=True),
                adapter=ticket_adapter,
                idempotency_key=idempotency_key,
            )
        except AuthenticationFailed as exc:
            raise HTTPException(status_code=401, detail="credential verification failed",
                                headers={"WWW-Authenticate": "Bearer"}) from exc
        except IdentityProviderUnavailable as exc:
            raise HTTPException(status_code=503, detail="identity provider unavailable") from exc
        except ContextUnavailable as exc:
            raise HTTPException(status_code=503, detail="trusted authorization context unavailable") from exc
        except PolicyUnavailable as exc:
            raise HTTPException(status_code=503, detail="policy decision service unavailable") from exc
        except IdempotencyConflict as exc:
            raise HTTPException(status_code=409, detail="idempotency key conflicts with another request") from exc
        except EffectOutcomeUnknown as exc:
            raise HTTPException(
                status_code=409,
                detail="operation outcome is unknown; reconcile downstream state before using a new key",
            ) from exc
        except PermitRejected as exc:
            raise HTTPException(status_code=403, detail="operation denied or permit no longer valid") from exc

    return app


