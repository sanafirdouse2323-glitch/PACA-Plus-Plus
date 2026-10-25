from __future__ import annotations

from contextlib import asynccontextmanager
import logging
import re
from typing import Any
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .adapters import (
    AdapterNotFound,
    AdapterRouter,
    EffectOutcomeUnknown,
    EffectRejected,
    EffectRequest,
)
from .auth import AuthenticationError, IdentityProviderUnavailable, JWTAuthenticator, Principal
from .config import Settings
from .context import AuthorizationContextProvider, ResourceNotFound
from .opa import OPAClient, PolicyEngineUnavailable
from .security import InvalidCanonicalValue, canonical_digest


logger = logging.getLogger("paca_service")
_ACTION_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")


class OperationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=1, max_length=128)
    resource_id: str = Field(min_length=1, max_length=256)
    arguments: dict[str, Any] = Field(default_factory=dict)

    @field_validator("action")
    @classmethod
    def valid_action(cls, value: str) -> str:
        if not _ACTION_RE.fullmatch(value):
            raise ValueError("invalid_action_identifier")
        return value

    @field_validator("resource_id")
    @classmethod
    def valid_resource_id(cls, value: str) -> str:
        if not value.strip() or "\x00" in value:
            raise ValueError("invalid_resource_identifier")
        return value

    @field_validator("arguments")
    @classmethod
    def finite_json_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            canonical_digest(value)
        except InvalidCanonicalValue as exc:
            raise ValueError("arguments_must_be_finite_json") from exc
        if len(str(value)) > 250_000:
            raise ValueError("arguments_size_limit_exceeded")
        return value




class ExecuteRequest(OperationRequest):
    permit_id: UUID

def create_app(
    settings: Settings,
    store: Any,
    opa: OPAClient,
    authenticator: JWTAuthenticator,
    adapter_router: AdapterRouter,
    context_provider: AuthorizationContextProvider | None = None,
) -> FastAPI:
    context_provider = context_provider or AuthorizationContextProvider(store)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            store.open()
            store.ping()
            store.mark_stale_executions_unknown(settings.stale_execution_seconds)
            yield
        finally:
            try:
                adapter_router.close()
            finally:
                try:
                    opa.close()
                finally:
                    store.close()

    app = FastAPI(
        title="PACA++ Authorization Service",
        version="0.1.0",
        description=(
            "Authorization enforcement gateway. OPA makes policy decisions; this service "
            "validates identity, retrieves trusted context, and guards external effects."
        ),
        lifespan=lifespan,
    )
    bearer = HTTPBearer(auto_error=False)

    @app.middleware("http")
    async def request_identifier(request: Request, call_next: Any) -> Response:
        request.state.request_id = uuid4().hex
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    def current_principal(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> Principal:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=401,
                detail={"code": "bearer_token_required"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            return authenticator.authenticate(credentials.credentials)
        except AuthenticationError as exc:
            raise HTTPException(
                status_code=401,
                detail={"code": str(exc)},
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        except IdentityProviderUnavailable as exc:
            raise HTTPException(status_code=503, detail={"code": str(exc)}) from exc

    def request_id(request: Request) -> str:
        return request.state.request_id

    def record_audit_or_503(**kwargs: Any) -> None:
        try:
            store.record_audit(**kwargs)
        except Exception as exc:
            logger.exception("durable audit write failed")
            raise HTTPException(status_code=503, detail={"code": "audit_store_unavailable"}) from exc

    def build_context_or_respond(
        principal: Principal, operation: OperationRequest
    ) -> dict[str, Any]:
        try:
            context = context_provider.build(
                principal, operation.action, operation.resource_id, operation.arguments
            )
            canonical_digest(context)
            return context
        except ResourceNotFound as exc:
            raise HTTPException(status_code=404, detail={"code": "resource_not_found"}) from exc
        except InvalidCanonicalValue as exc:
            logger.exception("trusted authorization context is not canonical JSON")
            raise HTTPException(status_code=503, detail={"code": "authorization_context_invalid"}) from exc
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("trusted context retrieval failed")
            raise HTTPException(status_code=503, detail={"code": "authorization_context_unavailable"}) from exc

    def evaluate_or_503(context: dict[str, Any]) -> Any:
        try:
            return opa.evaluate(context)
        except PolicyEngineUnavailable as exc:
            logger.warning("OPA decision unavailable: %s", str(exc))
            raise HTTPException(status_code=503, detail={"code": "policy_decision_unavailable"}) from exc
        except Exception as exc:
            logger.exception("unexpected policy decision failure")
            raise HTTPException(status_code=503, detail={"code": "policy_decision_unavailable"}) from exc

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/readyz")
    def readyz() -> dict[str, str]:
        try:
            store.ping()
            opa.health()
        except Exception as exc:
            logger.warning("readiness check failed")
            raise HTTPException(status_code=503, detail={"status": "not_ready"}) from exc
        return {"status": "ready"}

    @app.post("/v1/authorizations", status_code=201)
    def authorize_operation(
        operation: OperationRequest,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> dict[str, Any]:
        rid = request_id(request)
        argument_hash = canonical_digest(operation.arguments)
        try:
            context = build_context_or_respond(principal, operation)
        except HTTPException as exc:
            if exc.status_code == 404:
                record_audit_or_503(
                    event_type="authorization_denied", tenant_id=principal.tenant_id,
                    principal_id=principal.subject, request_id=rid, action=operation.action,
                    resource_id=operation.resource_id, reason_code="resource_not_found",
                    arguments_digest=argument_hash,
                )
            raise

        context_hash = canonical_digest(context)
        decision = evaluate_or_503(context)
        if not decision.allowed:
            record_audit_or_503(
                event_type="authorization_denied", tenant_id=principal.tenant_id,
                principal_id=principal.subject, request_id=rid, action=operation.action,
                resource_id=operation.resource_id, reason_code=decision.reason,
                policy_revision=decision.policy_revision, decision_id=decision.decision_id,
                arguments_digest=argument_hash, context_digest=context_hash,
            )
            raise HTTPException(status_code=403, detail={"code": "authorization_denied"})

        try:
            permit = store.issue_permit(
                tenant_id=principal.tenant_id,
                principal_id=principal.subject,
                action=operation.action,
                resource_id=operation.resource_id,
                arguments_digest=argument_hash,
                context_digest=context_hash,
                policy_revision=decision.policy_revision,
                decision_id=decision.decision_id,
                ttl_seconds=settings.permit_ttl_seconds,
                request_id=rid,
            )
        except Exception as exc:
            logger.exception("permit issuance transaction failed")
            raise HTTPException(status_code=503, detail={"code": "permit_store_unavailable"}) from exc
        return {
            "permit_id": permit.permit_id,
            "status": permit.status,
            "expires_at": permit.expires_at.isoformat(),
            "policy_revision": permit.policy_revision,
            "request_id": rid,
        }

    @app.post("/v1/executions")
    def execute_operation(
        operation: ExecuteRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key"),
        principal: Principal = Depends(current_principal),
    ) -> Any:
        rid = request_id(request)
        if not _IDEMPOTENCY_RE.fullmatch(idempotency_key):
            raise HTTPException(status_code=400, detail={"code": "invalid_idempotency_key"})
        permit_id = operation.permit_id

        try:
            permit = store.get_permit(permit_id, principal.tenant_id, principal.subject)
        except Exception as exc:
            logger.exception("permit lookup failed")
            raise HTTPException(status_code=503, detail={"code": "permit_store_unavailable"}) from exc
        if permit is None:
            raise HTTPException(status_code=404, detail={"code": "permit_not_found"})

        argument_hash = canonical_digest(operation.arguments)
        if operation.action != permit.action or operation.resource_id != permit.resource_id:
            record_audit_or_503(
                event_type="execution_rejected", tenant_id=principal.tenant_id,
                principal_id=principal.subject, request_id=rid, action=operation.action,
                resource_id=operation.resource_id, permit_id=permit_id,
                reason_code="operation_mismatch", arguments_digest=argument_hash,
            )
            raise HTTPException(status_code=409, detail={"code": "operation_mismatch"})
        if argument_hash != permit.arguments_digest:
            record_audit_or_503(
                event_type="execution_rejected", tenant_id=principal.tenant_id,
                principal_id=principal.subject, request_id=rid, action=operation.action,
                resource_id=operation.resource_id, permit_id=permit_id,
                reason_code="arguments_mismatch", arguments_digest=argument_hash,
            )
            raise HTTPException(status_code=409, detail={"code": "arguments_mismatch"})

        try:
            context = context_provider.build(
                principal, operation.action, operation.resource_id, operation.arguments
            )
            context_hash = canonical_digest(context)
        except ResourceNotFound as exc:
            try:
                store.revoke_permit(
                    permit_id, principal.tenant_id, principal.subject, "resource_not_found", rid
                )
            except Exception:
                logger.exception("failed to revoke permit after resource loss")
            raise HTTPException(status_code=404, detail={"code": "resource_not_found"}) from exc
        except Exception as exc:
            logger.exception("execution context retrieval failed")
            raise HTTPException(status_code=503, detail={"code": "authorization_context_unavailable"}) from exc

        if context_hash != permit.context_digest:
            try:
                store.revoke_permit(
                    permit_id, principal.tenant_id, principal.subject, "context_changed", rid
                )
                store.record_audit(
                    event_type="execution_rejected", tenant_id=principal.tenant_id,
                    principal_id=principal.subject, request_id=rid, action=operation.action,
                    resource_id=operation.resource_id, permit_id=permit_id,
                    reason_code="context_changed", arguments_digest=argument_hash,
                    context_digest=context_hash, policy_revision=permit.policy_revision,
                )
            except Exception as exc:
                logger.exception("context-change audit/revocation failed")
                raise HTTPException(status_code=503, detail={"code": "audit_store_unavailable"}) from exc
            raise HTTPException(status_code=409, detail={"code": "context_changed_reauthorize"})

        decision = evaluate_or_503(context)
        if not decision.allowed:
            try:
                store.revoke_permit(
                    permit_id, principal.tenant_id, principal.subject, decision.reason, rid
                )
                store.record_audit(
                    event_type="execution_rejected", tenant_id=principal.tenant_id,
                    principal_id=principal.subject, request_id=rid, action=operation.action,
                    resource_id=operation.resource_id, permit_id=permit_id,
                    reason_code=decision.reason, arguments_digest=argument_hash,
                    context_digest=context_hash, policy_revision=decision.policy_revision,
                    decision_id=decision.decision_id,
                )
            except Exception as exc:
                logger.exception("policy-denial audit/revocation failed")
                raise HTTPException(status_code=503, detail={"code": "audit_store_unavailable"}) from exc
            raise HTTPException(status_code=403, detail={"code": "authorization_denied_at_execution"})
        if decision.policy_revision != permit.policy_revision:
            try:
                store.revoke_permit(
                    permit_id, principal.tenant_id, principal.subject, "stale_policy", rid
                )
            except Exception:
                logger.exception("stale-policy permit revocation failed")
            raise HTTPException(status_code=409, detail={"code": "stale_policy_reauthorize"})

        try:
            adapter = adapter_router.choose(operation.action, operation.arguments, context)
        except AdapterNotFound as exc:
            record_audit_or_503(
                event_type="execution_rejected", tenant_id=principal.tenant_id,
                principal_id=principal.subject, request_id=rid, action=operation.action,
                resource_id=operation.resource_id, permit_id=permit_id,
                reason_code="no_adapter_for_operation", arguments_digest=argument_hash,
                context_digest=context_hash, policy_revision=decision.policy_revision,
                decision_id=decision.decision_id,
            )
            raise HTTPException(status_code=422, detail={"code": "no_adapter_for_operation"}) from exc
        except Exception as exc:
            logger.exception("ambiguous adapter configuration")
            raise HTTPException(status_code=503, detail={"code": "adapter_configuration_error"}) from exc

        try:
            claim = store.claim_execution(
                permit_id=permit_id, tenant_id=principal.tenant_id, principal_id=principal.subject,
                action=operation.action, resource_id=operation.resource_id,
                arguments_digest=argument_hash, context_digest=context_hash,
                policy_revision=decision.policy_revision, idempotency_key=idempotency_key,
                context=context, request_id=rid,
            )
        except Exception as exc:
            logger.exception("atomic execution claim failed")
            raise HTTPException(status_code=503, detail={"code": "execution_store_unavailable"}) from exc

        if claim.disposition == "replayed_success":
            return {
                "execution_id": claim.execution_id,
                "status": "succeeded",
                "result": claim.result or {},
                "idempotent_replay": True,
            }
        if claim.disposition == "in_progress":
            raise HTTPException(
                status_code=409,
                detail={"code": "execution_in_progress", "execution_id": claim.execution_id},
            )
        if claim.disposition == "outcome_unknown":
            return JSONResponse(
                status_code=202,
                content={
                    "execution_id": claim.execution_id,
                    "status": "unknown",
                    "code": "execution_outcome_unknown",
                    "retry_safe": False,
                },
            )
        if claim.disposition == "failed":
            raise HTTPException(
                status_code=502,
                detail={"code": "prior_execution_failed", "execution_id": claim.execution_id},
            )
        if claim.disposition == "conflict":
            raise HTTPException(status_code=409, detail={"code": claim.reason or "idempotency_conflict"})
        if claim.disposition != "claimed" or not claim.execution_id:
            status_code = 404 if claim.reason == "invalid_permit" else 409
            raise HTTPException(status_code=status_code, detail={"code": claim.reason or "permit_rejected"})

        effect_request = EffectRequest(
            execution_id=claim.execution_id,
            principal=principal,
            action=operation.action,
            resource_id=operation.resource_id,
            arguments=operation.arguments,
            context=context,
        )
        try:
            result = adapter.execute(effect_request)
        except EffectRejected as exc:
            try:
                store.finish_execution(
                    execution_id=claim.execution_id, outcome="failed",
                    result={"status": "failed"}, error_code=exc.code, request_id=rid,
                )
            except Exception:
                logger.exception("failed effect outcome could not be persisted")
                return JSONResponse(
                    status_code=202,
                    content={
                        "execution_id": claim.execution_id,
                        "status": "unknown",
                        "code": "execution_finalization_pending",
                        "retry_safe": False,
                    },
                )
            raise HTTPException(
                status_code=502,
                detail={"code": "protected_operation_rejected", "execution_id": claim.execution_id},
            ) from exc
        except EffectOutcomeUnknown as exc:
            try:
                store.finish_execution(
                    execution_id=claim.execution_id, outcome="unknown", result=None,
                    error_code=exc.code, request_id=rid,
                )
            except Exception:
                logger.exception("uncertain effect outcome could not be persisted")
            return JSONResponse(
                status_code=202,
                content={
                    "execution_id": claim.execution_id,
                    "status": "unknown",
                    "code": "execution_outcome_unknown",
                    "retry_safe": False,
                },
            )
        except Exception:
            # A handler may have completed an effect before raising. Never auto-retry it.
            logger.exception("adapter failed with an uncertain outcome")
            try:
                store.finish_execution(
                    execution_id=claim.execution_id, outcome="unknown", result=None,
                    error_code="adapter_unexpected_error", request_id=rid,
                )
            except Exception:
                logger.exception("uncertain adapter outcome could not be persisted")
            return JSONResponse(
                status_code=202,
                content={
                    "execution_id": claim.execution_id,
                    "status": "unknown",
                    "code": "execution_outcome_unknown",
                    "retry_safe": False,
                },
            )

        try:
            store.finish_execution(
                execution_id=claim.execution_id, outcome="succeeded",
                result=result, error_code=None, request_id=rid,
            )
        except Exception:
            # External work already returned success, but durable completion failed.
            # Recovery will classify the stale execution as unknown; do not call again.
            logger.exception("successful effect result could not be persisted")
            return JSONResponse(
                status_code=202,
                content={
                    "execution_id": claim.execution_id,
                    "status": "unknown",
                    "code": "execution_finalization_pending",
                    "retry_safe": False,
                },
            )
        return {
            "execution_id": claim.execution_id,
            "status": "succeeded",
            "result": result,
            "idempotent_replay": False,
        }

    @app.get("/v1/executions/{execution_id}")
    def execution_status(
        execution_id: UUID,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> dict[str, Any]:
        try:
            status = store.get_execution_status(
                execution_id, principal.tenant_id, principal.subject
            )
        except Exception as exc:
            logger.exception("execution status lookup failed")
            raise HTTPException(status_code=503, detail={"code": "execution_store_unavailable"}) from exc
        if status is None:
            raise HTTPException(status_code=404, detail={"code": "execution_not_found"})
        return {"request_id": request_id(request), **status}

    return app
