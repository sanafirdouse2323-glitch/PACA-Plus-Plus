from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
import re
from typing import Any
from uuid import UUID, uuid4

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from .security import canonical_digest


_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")


class StoreError(RuntimeError):
    """Database operation failed; callers must fail closed."""


@dataclass(frozen=True)
class PermitRecord:
    permit_id: str
    tenant_id: str
    principal_id: str
    action: str
    resource_id: str
    arguments_digest: str
    context_digest: str
    policy_revision: str
    decision_id: str | None
    status: str
    expires_at: datetime


@dataclass(frozen=True)
class ClaimResult:
    disposition: str
    execution_id: str | None = None
    status: str | None = None
    result: dict[str, Any] | None = None
    reason: str | None = None


class PostgresStore:
    """PostgreSQL-backed permits, idempotency, execution state, resources and audit."""

    def __init__(self, database_url: str, pool: ConnectionPool | None = None) -> None:
        self.pool = pool or ConnectionPool(
            conninfo=database_url,
            min_size=1,
            max_size=12,
            timeout=5,
            kwargs={"row_factory": dict_row},
            open=False,
        )
        self._owns_pool = pool is None

    def open(self) -> None:
        self.pool.open(wait=True)

    def close(self) -> None:
        if self._owns_pool:
            self.pool.close()

    def ping(self) -> None:
        with self.pool.connection() as conn:
            conn.execute("SELECT 1").fetchone()

    def fetch_resource(self, tenant_id: str, resource_id: str) -> dict[str, Any] | None:
        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('paca.tenant_id', %s, true)", (tenant_id,))
            row = conn.execute(
                """
                SELECT tenant_id, resource_id, owner_id, kind, status, attributes
                FROM protected_resources
                WHERE tenant_id = %s AND resource_id = %s
                """,
                (tenant_id, resource_id),
            ).fetchone()
        return dict(row) if row else None

    def issue_permit(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        action: str,
        resource_id: str,
        arguments_digest: str,
        context_digest: str,
        policy_revision: str,
        decision_id: str | None,
        ttl_seconds: int,
        request_id: str | None,
    ) -> PermitRecord:
        permit_id = uuid4()
        expires_at = datetime.now(UTC) + timedelta(seconds=ttl_seconds)
        with self.pool.connection() as conn, conn.transaction():
                conn.execute("SELECT set_config('paca.tenant_id', %s, true)", (tenant_id,))
                conn.execute(
                    """
                    INSERT INTO authz_permits
                    (permit_id, tenant_id, principal_id, action, resource_id, arguments_digest,
                     context_digest, policy_revision, decision_id, status, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'issued', %s)
                    """,
                    (
                        permit_id, tenant_id, principal_id, action, resource_id,
                        arguments_digest, context_digest, policy_revision, decision_id, expires_at,
                    ),
                )
                self._audit(
                    conn, request_id=request_id, tenant_id=tenant_id, principal_id=principal_id,
                    event_type="permit_issued", action=action, resource_id=resource_id,
                    permit_id=permit_id, policy_revision=policy_revision, decision_id=decision_id,
                    arguments_digest=arguments_digest, context_digest=context_digest,
                    details={"ttl_seconds": ttl_seconds},
                )
        return PermitRecord(
            permit_id=str(permit_id), tenant_id=tenant_id, principal_id=principal_id,
            action=action, resource_id=resource_id, arguments_digest=arguments_digest,
            context_digest=context_digest, policy_revision=policy_revision, decision_id=decision_id,
            status="issued", expires_at=expires_at,
        )

    def get_permit(
        self, permit_id: UUID | str, tenant_id: str, principal_id: str
    ) -> PermitRecord | None:
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM authz_permits
                WHERE permit_id = %s AND tenant_id = %s AND principal_id = %s
                """,
                (UUID(str(permit_id)), tenant_id, principal_id),
            ).fetchone()
        return self._permit(row) if row else None

    def revoke_permit(
        self, permit_id: UUID | str, tenant_id: str, principal_id: str, reason: str,
        request_id: str | None,
    ) -> None:
        with self.pool.connection() as conn, conn.transaction():
                row = conn.execute(
                    """
                    UPDATE authz_permits SET status = 'revoked', updated_at = now()
                    WHERE permit_id = %s AND tenant_id = %s AND principal_id = %s AND status = 'issued'
                    RETURNING action, resource_id, policy_revision, arguments_digest, context_digest
                    """,
                    (UUID(str(permit_id)), tenant_id, principal_id),
                ).fetchone()
                if row:
                    self._audit(
                        conn, request_id=request_id, tenant_id=tenant_id, principal_id=principal_id,
                        event_type="permit_revoked", action=row["action"], resource_id=row["resource_id"],
                        permit_id=UUID(str(permit_id)), reason_code=reason,
                        policy_revision=row["policy_revision"],
                        arguments_digest=row["arguments_digest"], context_digest=row["context_digest"],
                    )

    def record_audit(
        self, *, event_type: str, tenant_id: str | None, principal_id: str | None,
        request_id: str | None, action: str | None = None, resource_id: str | None = None,
        permit_id: UUID | str | None = None, execution_id: UUID | str | None = None,
        reason_code: str | None = None, policy_revision: str | None = None,
        decision_id: str | None = None, arguments_digest: str | None = None,
        context_digest: str | None = None, details: dict[str, Any] | None = None,
    ) -> None:
        with self.pool.connection() as conn, conn.transaction():
                self._audit(
                    conn, event_type=event_type, tenant_id=tenant_id, principal_id=principal_id,
                    request_id=request_id, action=action, resource_id=resource_id,
                    permit_id=UUID(str(permit_id)) if permit_id else None,
                    execution_id=UUID(str(execution_id)) if execution_id else None,
                    reason_code=reason_code, policy_revision=policy_revision,
                    decision_id=decision_id, arguments_digest=arguments_digest,
                    context_digest=context_digest, details=details,
                )

    def claim_execution(
        self, *, permit_id: UUID | str, tenant_id: str, principal_id: str,
        action: str, resource_id: str, arguments_digest: str, context_digest: str,
        policy_revision: str, idempotency_key: str, context: dict[str, Any],
        request_id: str | None,
    ) -> ClaimResult:
        if not _IDEMPOTENCY_KEY.fullmatch(idempotency_key):
            return ClaimResult("rejected", reason="invalid_idempotency_key")
        permit_uuid = UUID(str(permit_id))
        request_digest = canonical_digest({
            "permit_id": str(permit_uuid), "action": action, "resource_id": resource_id,
            "arguments_digest": arguments_digest, "context_digest": context_digest,
            "policy_revision": policy_revision,
        })
        with self.pool.connection() as conn, conn.transaction():
                conn.execute("SELECT set_config('paca.tenant_id', %s, true)", (tenant_id,))
                existing = conn.execute(
                    """
                    SELECT execution_id, request_digest, status, result_json, error_code
                    FROM authz_executions
                    WHERE tenant_id = %s AND principal_id = %s AND idempotency_key = %s
                    FOR UPDATE
                    """,
                    (tenant_id, principal_id, idempotency_key),
                ).fetchone()
                if existing:
                    return self._existing_claim(existing, request_digest)

                permit = conn.execute(
                    """
                    SELECT * FROM authz_permits
                    WHERE permit_id = %s AND tenant_id = %s AND principal_id = %s
                    FOR UPDATE
                    """,
                    (permit_uuid, tenant_id, principal_id),
                ).fetchone()
                if not permit:
                    self._audit(
                        conn, request_id=request_id, tenant_id=tenant_id, principal_id=principal_id,
                        event_type="execution_rejected", reason_code="invalid_permit",
                        action=action, resource_id=resource_id, permit_id=permit_uuid,
                    )
                    return ClaimResult("rejected", reason="invalid_permit")

                mismatch = None
                if permit["status"] != "issued":
                    prior_by_permit = conn.execute(
                        """
                        SELECT execution_id, idempotency_key, request_digest, status, result_json, error_code
                        FROM authz_executions WHERE permit_id = %s FOR UPDATE
                        """,
                        (permit_uuid,),
                    ).fetchone()
                    if prior_by_permit and prior_by_permit["idempotency_key"] == idempotency_key:
                        return self._existing_claim(prior_by_permit, request_digest)
                    mismatch = "permit_not_issued"
                elif permit["expires_at"] <= datetime.now(UTC):
                    conn.execute(
                        "UPDATE authz_permits SET status = 'expired', updated_at = now() WHERE permit_id = %s",
                        (permit_uuid,),
                    )
                    mismatch = "permit_expired"
                elif permit["action"] != action or permit["resource_id"] != resource_id:
                    mismatch = "operation_mismatch"
                elif permit["arguments_digest"].strip() != arguments_digest:
                    mismatch = "arguments_mismatch"
                elif permit["policy_revision"] != policy_revision:
                    mismatch = "stale_policy"
                elif permit["context_digest"].strip() != context_digest:
                    mismatch = "context_changed"

                if not mismatch:
                    resource = conn.execute(
                        """
                        SELECT tenant_id, resource_id, owner_id, kind, status, attributes
                        FROM protected_resources
                        WHERE tenant_id = %s AND resource_id = %s
                        FOR SHARE
                        """,
                        (tenant_id, resource_id),
                    ).fetchone()
                    if not resource:
                        mismatch = "resource_not_found"
                    else:
                        locked_context = {
                            "principal": context.get("principal"),
                            "action": action,
                            "resource": {
                                "id": resource["resource_id"],
                                "tenant_id": resource["tenant_id"],
                                "owner_id": resource["owner_id"],
                                "kind": resource["kind"],
                                "status": resource["status"],
                                "attributes": resource["attributes"] or {},
                            },
                            "arguments": context.get("arguments"),
                        }
                        if canonical_digest(locked_context) != context_digest:
                            mismatch = "context_changed"

                if mismatch:
                    if mismatch in {"context_changed", "resource_not_found", "stale_policy"}:
                        conn.execute(
                            """
                            UPDATE authz_permits SET status = 'revoked', updated_at = now()
                            WHERE permit_id = %s AND status = 'issued'
                            """,
                            (permit_uuid,),
                        )
                    self._audit(
                        conn, request_id=request_id, tenant_id=tenant_id, principal_id=principal_id,
                        event_type="execution_rejected", reason_code=mismatch, action=action,
                        resource_id=resource_id, permit_id=permit_uuid,
                        policy_revision=permit["policy_revision"],
                        arguments_digest=arguments_digest, context_digest=context_digest,
                    )
                    return ClaimResult("rejected", reason=mismatch)

                execution_id = uuid4()
                inserted = conn.execute(
                    """
                    INSERT INTO authz_executions
                    (execution_id, permit_id, tenant_id, principal_id, idempotency_key,
                     request_digest, status)
                    VALUES (%s, %s, %s, %s, %s, %s, 'executing')
                    ON CONFLICT DO NOTHING
                    RETURNING execution_id
                    """,
                    (execution_id, permit_uuid, tenant_id, principal_id, idempotency_key, request_digest),
                ).fetchone()
                if not inserted:
                    conflict = conn.execute(
                        """
                        SELECT execution_id, request_digest, status, result_json, error_code
                        FROM authz_executions
                        WHERE permit_id = %s OR
                              (tenant_id = %s AND principal_id = %s AND idempotency_key = %s)
                        ORDER BY created_at DESC LIMIT 1 FOR UPDATE
                        """,
                        (permit_uuid, tenant_id, principal_id, idempotency_key),
                    ).fetchone()
                    if conflict:
                        return self._existing_claim(conflict, request_digest)
                    return ClaimResult("conflict", reason="idempotency_conflict")

                conn.execute(
                    "UPDATE authz_permits SET status = 'executing', updated_at = now() WHERE permit_id = %s",
                    (permit_uuid,),
                )
                self._audit(
                    conn, request_id=request_id, tenant_id=tenant_id, principal_id=principal_id,
                    event_type="execution_started", action=action, resource_id=resource_id,
                    permit_id=permit_uuid, execution_id=execution_id,
                    policy_revision=policy_revision, arguments_digest=arguments_digest,
                    context_digest=context_digest,
                )
                return ClaimResult("claimed", execution_id=str(execution_id), status="executing")

    def finish_execution(
        self, *, execution_id: UUID | str, outcome: str, result: dict[str, Any] | None,
        error_code: str | None, request_id: str | None,
    ) -> None:
        if outcome not in {"succeeded", "failed", "unknown"}:
            raise ValueError("invalid_execution_outcome")
        if result is not None:
            json.dumps(result, allow_nan=False)
        execution_uuid = UUID(str(execution_id))
        with self.pool.connection() as conn, conn.transaction():
                row = conn.execute(
                    """
                    UPDATE authz_executions
                    SET status = %s, result_json = %s, error_code = %s, finished_at = now()
                    WHERE execution_id = %s AND status = 'executing'
                    RETURNING permit_id, tenant_id, principal_id
                    """,
                    (
                        outcome, Jsonb(result) if result is not None else None,
                        error_code, execution_uuid,
                    ),
                ).fetchone()
                if not row:
                    raise StoreError("execution_state_changed_before_completion")
                conn.execute(
                    "UPDATE authz_permits SET status = %s, updated_at = now() WHERE permit_id = %s",
                    (outcome, row["permit_id"]),
                )
                self._audit(
                    conn, request_id=request_id, tenant_id=row["tenant_id"],
                    principal_id=row["principal_id"], event_type=f"execution_{outcome}",
                    permit_id=row["permit_id"], execution_id=execution_uuid,
                    reason_code=error_code,
                )


    def get_execution_status(
        self, execution_id: UUID | str, tenant_id: str, principal_id: str
    ) -> dict[str, Any] | None:
        """Return status metadata only; result data is retrievable only via the authorized idempotent retry."""
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT e.execution_id, e.status, e.error_code, e.created_at, e.started_at,
                       e.finished_at, p.action, p.resource_id, p.policy_revision
                FROM authz_executions e
                JOIN authz_permits p ON p.permit_id = e.permit_id
                WHERE e.execution_id = %s AND e.tenant_id = %s AND e.principal_id = %s
                """,
                (UUID(str(execution_id)), tenant_id, principal_id),
            ).fetchone()
        if not row:
            return None
        return {
            "execution_id": str(row["execution_id"]),
            "status": row["status"],
            "error_code": row["error_code"],
            "action": row["action"],
            "resource_id": row["resource_id"],
            "policy_revision": row["policy_revision"],
            "created_at": row["created_at"].isoformat(),
            "started_at": row["started_at"].isoformat(),
            "finished_at": row["finished_at"].isoformat() if row["finished_at"] else None,
        }

    def mark_stale_executions_unknown(self, stale_after_seconds: int) -> int:
        """Mark abandoned executions unknown; never automatically replay external effects."""
        count = 0
        with self.pool.connection() as conn, conn.transaction():
                rows = conn.execute(
                    """
                    UPDATE authz_executions
                    SET status = 'unknown', error_code = 'stale_execution_recovered',
                        finished_at = now()
                    WHERE status = 'executing'
                      AND started_at < now() - (%s * interval '1 second')
                    RETURNING execution_id, permit_id, tenant_id, principal_id
                    """,
                    (stale_after_seconds,),
                ).fetchall()
                for row in rows:
                    conn.execute(
                        "UPDATE authz_permits SET status = 'unknown', updated_at = now() WHERE permit_id = %s",
                        (row["permit_id"],),
                    )
                    self._audit(
                        conn, tenant_id=row["tenant_id"], principal_id=row["principal_id"],
                        event_type="execution_unknown", permit_id=row["permit_id"],
                        execution_id=row["execution_id"], reason_code="stale_execution_recovered",
                    )
                count = len(rows)
        return count

    @staticmethod
    def _existing_claim(existing: dict[str, Any], request_digest: str) -> ClaimResult:
        if existing["request_digest"].strip() != request_digest:
            return ClaimResult("conflict", reason="idempotency_key_reused_for_different_request")
        status = existing["status"]
        result = existing.get("result_json")
        if status == "succeeded":
            return ClaimResult(
                "replayed_success", execution_id=str(existing["execution_id"]),
                status=status, result=result if isinstance(result, dict) else {},
            )
        if status == "executing":
            return ClaimResult("in_progress", execution_id=str(existing["execution_id"]), status=status)
        if status == "unknown":
            return ClaimResult(
                "outcome_unknown", execution_id=str(existing["execution_id"]),
                status=status, reason=existing.get("error_code") or "execution_outcome_unknown",
            )
        return ClaimResult(
            "failed", execution_id=str(existing["execution_id"]), status=status,
            reason=existing.get("error_code") or "execution_failed",
        )

    @staticmethod
    def _permit(row: dict[str, Any]) -> PermitRecord:
        return PermitRecord(
            permit_id=str(row["permit_id"]), tenant_id=row["tenant_id"], principal_id=row["principal_id"],
            action=row["action"], resource_id=row["resource_id"],
            arguments_digest=row["arguments_digest"].strip(), context_digest=row["context_digest"].strip(),
            policy_revision=row["policy_revision"], decision_id=row["decision_id"], status=row["status"],
            expires_at=row["expires_at"],
        )

    @staticmethod
    def _audit(
        conn: Any, *, event_type: str, tenant_id: str | None, principal_id: str | None,
        request_id: str | None = None, action: str | None = None, resource_id: str | None = None,
        permit_id: UUID | None = None, execution_id: UUID | None = None,
        reason_code: str | None = None, policy_revision: str | None = None,
        decision_id: str | None = None, arguments_digest: str | None = None,
        context_digest: str | None = None, details: dict[str, Any] | None = None,
    ) -> None:
        conn.execute(
            """
            INSERT INTO audit_events
            (request_id, tenant_id, principal_id, event_type, action, resource_id, permit_id,
             execution_id, reason_code, policy_revision, decision_id, arguments_digest,
             context_digest, details)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                request_id, tenant_id, principal_id, event_type, action, resource_id, permit_id,
                execution_id, reason_code, policy_revision, decision_id, arguments_digest,
                context_digest, Jsonb(details or {}),
            ),
        )
