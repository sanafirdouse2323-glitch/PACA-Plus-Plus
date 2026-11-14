"""Transactional operation journal for PACA++-guarded LangGraph tools.

The journal is deliberately separate from LangGraph's checkpointer and BaseStore:
it serializes one protected effect across workers, stores the PACA permit before
execution, and keeps the original idempotency key available after process restart.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, replace
from typing import Any
from uuid import UUID, uuid4

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool


class OperationLedgerError(RuntimeError):
    """The durable operation ledger could not safely record or recover an operation."""


class OperationInProgress(OperationLedgerError):
    """Another worker currently owns the short execution lease for this operation."""


@dataclass(frozen=True)
class OperationRecord:
    tool_name: str
    action: str
    request_fingerprint: str
    permit_id: str
    idempotency_key: str
    status: str
    result: dict[str, Any] | None = None
    execution_id: str | None = None


@dataclass(frozen=True)
class ExecutionClaim:
    record: OperationRecord
    token: str | None


def _identity(thread_id: str, tool_call_id: str) -> tuple[str, str]:
    if not isinstance(thread_id, str) or not thread_id or len(thread_id) > 256:
        raise OperationLedgerError("langgraph_thread_id_required")
    if not isinstance(tool_call_id, str) or not tool_call_id or len(tool_call_id) > 128:
        raise OperationLedgerError("langgraph_tool_call_id_required")
    return (
        hashlib.sha256(thread_id.encode("utf-8")).hexdigest(),
        hashlib.sha256(tool_call_id.encode("utf-8")).hexdigest(),
    )


def _validate_record(
    record: OperationRecord,
    *,
    tool_name: str,
    action: str,
    request_fingerprint: str,
    idempotency_key: str,
) -> OperationRecord:
    if (
        record.tool_name != tool_name
        or record.action != action
        or record.request_fingerprint != request_fingerprint
        or record.idempotency_key != idempotency_key
    ):
        raise OperationLedgerError("paca_execution_journal_conflict")
    try:
        canonical_permit = str(UUID(record.permit_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise OperationLedgerError("paca_execution_journal_has_invalid_permit") from exc
    if canonical_permit != record.permit_id:
        raise OperationLedgerError("paca_execution_journal_has_noncanonical_permit")
    if record.status not in {"authorized", "succeeded", "failed", "unknown"}:
        raise OperationLedgerError("paca_execution_journal_has_invalid_status")
    if record.result is not None:
        try:
            json.dumps(record.result, allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise OperationLedgerError("paca_execution_journal_result_invalid") from exc
    return record


class InMemoryOperationLedger:
    """Thread-safe test double. Never use this for a multi-process deployment."""

    def __init__(self, *, claim_ttl_seconds: float = 120.0) -> None:
        if (
            isinstance(claim_ttl_seconds, bool)
            or not isinstance(claim_ttl_seconds, (int, float))
            or claim_ttl_seconds <= 0
        ):
            raise ValueError("claim_ttl_seconds_must_be_positive")
        self.claim_ttl_seconds = float(claim_ttl_seconds)
        self._records: dict[tuple[str, str], OperationRecord] = {}
        self._leases: dict[tuple[str, str], tuple[str, float]] = {}
        self._lock = threading.RLock()

    def get(self, thread_id: str, tool_call_id: str) -> OperationRecord | None:
        key = _identity(thread_id, tool_call_id)
        with self._lock:
            return self._records.get(key)

    def save_authorization(
        self,
        *,
        thread_id: str,
        tool_call_id: str,
        tool_name: str,
        action: str,
        request_fingerprint: str,
        permit_id: str,
        idempotency_key: str,
    ) -> OperationRecord:
        key = _identity(thread_id, tool_call_id)
        candidate = OperationRecord(
            tool_name, action, request_fingerprint, permit_id, idempotency_key, "authorized"
        )
        _validate_record(
            candidate,
            tool_name=tool_name,
            action=action,
            request_fingerprint=request_fingerprint,
            idempotency_key=idempotency_key,
        )
        with self._lock:
            existing = self._records.get(key)
            if existing is None:
                self._records[key] = candidate
                return candidate
            return _validate_record(
                existing,
                tool_name=tool_name,
                action=action,
                request_fingerprint=request_fingerprint,
                idempotency_key=idempotency_key,
            )

    def claim_execution(
        self,
        *,
        thread_id: str,
        tool_call_id: str,
        tool_name: str,
        action: str,
        request_fingerprint: str,
        idempotency_key: str,
    ) -> ExecutionClaim:
        key = _identity(thread_id, tool_call_id)
        with self._lock:
            record = self._records.get(key)
            if record is None:
                raise OperationLedgerError("paca_execution_journal_missing")
            record = _validate_record(
                record,
                tool_name=tool_name,
                action=action,
                request_fingerprint=request_fingerprint,
                idempotency_key=idempotency_key,
            )
            if record.status != "authorized":
                return ExecutionClaim(record, None)
            lease = self._leases.get(key)
            now = time.monotonic()
            if lease is not None and lease[1] > now:
                raise OperationInProgress("paca_operation_in_progress")
            token = str(uuid4())
            self._leases[key] = (token, now + self.claim_ttl_seconds)
            return ExecutionClaim(record, token)

    def complete_execution(
        self,
        *,
        thread_id: str,
        tool_call_id: str,
        claim_token: str,
        status: str,
        result: dict[str, Any],
        execution_id: str | None,
    ) -> OperationRecord:
        if status not in {"succeeded", "failed", "unknown"}:
            raise ValueError("invalid_terminal_operation_status")
        try:
            json.dumps(result, allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise OperationLedgerError("paca_execution_journal_result_invalid") from exc
        key = _identity(thread_id, tool_call_id)
        with self._lock:
            lease = self._leases.get(key)
            if lease is None or lease[0] != claim_token or lease[1] <= time.monotonic():
                raise OperationLedgerError("paca_execution_journal_lease_lost")
            current = self._records.get(key)
            if current is None or current.status != "authorized":
                raise OperationLedgerError("paca_execution_journal_state_conflict")
            updated = replace(
                current, status=status, result=dict(result), execution_id=execution_id
            )
            self._records[key] = updated
            self._leases.pop(key, None)
            return updated

    def release_execution(
        self, *, thread_id: str, tool_call_id: str, claim_token: str
    ) -> None:
        key = _identity(thread_id, tool_call_id)
        with self._lock:
            lease = self._leases.get(key)
            if lease is not None and lease[0] == claim_token:
                self._leases.pop(key, None)


class PostgresOperationLedger:
    """PostgreSQL transactional journal for multi-worker agent deployments.

    Apply agent/migrations/0001-operation-ledger.sql with a migration role first.
    Give the runtime role only USAGE on schema paca_langgraph and SELECT/INSERT/
    UPDATE on its execution_journal table. The database should be dedicated to
    LangGraph persistence and must not be the PACA service's signing-key database.
    """

    def __init__(
        self,
        database_url: str | None = None,
        *,
        pool: ConnectionPool | None = None,
        claim_ttl_seconds: float = 120.0,
    ) -> None:
        if (database_url is None) == (pool is None):
            raise ValueError("provide_exactly_one_of_database_url_or_pool")
        if (
            isinstance(claim_ttl_seconds, bool)
            or not isinstance(claim_ttl_seconds, (int, float))
            or claim_ttl_seconds <= 0
        ):
            raise ValueError("claim_ttl_seconds_must_be_positive")
        self.claim_ttl_seconds = float(claim_ttl_seconds)
        self._owns_pool = pool is None
        self.pool = pool or ConnectionPool(
            conninfo=database_url,
            min_size=1,
            max_size=8,
            timeout=10,
            kwargs={"row_factory": dict_row},
            open=False,
        )

    def open(self) -> None:
        self.pool.open(wait=True)

    def close(self) -> None:
        if self._owns_pool:
            self.pool.close()

    def ping(self) -> None:
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM paca_langgraph.execution_journal LIMIT 1"
            ).fetchone()
            del row

    @staticmethod
    def _row(row: dict[str, Any]) -> OperationRecord:
        return OperationRecord(
            tool_name=row["tool_name"],
            action=row["action"],
            request_fingerprint=row["request_fingerprint"].strip(),
            permit_id=str(row["permit_id"]),
            idempotency_key=row["idempotency_key"],
            status=row["status"],
            result=row["result_json"],
            execution_id=row["execution_id"],
        )

    def get(self, thread_id: str, tool_call_id: str) -> OperationRecord | None:
        thread_hash, call_hash = _identity(thread_id, tool_call_id)
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT tool_name, action, request_fingerprint, permit_id,
                       idempotency_key, status, result_json, execution_id
                FROM paca_langgraph.execution_journal
                WHERE thread_hash = %s AND tool_call_hash = %s
                """,
                (thread_hash, call_hash),
            ).fetchone()
        return self._row(row) if row else None

    def save_authorization(
        self,
        *,
        thread_id: str,
        tool_call_id: str,
        tool_name: str,
        action: str,
        request_fingerprint: str,
        permit_id: str,
        idempotency_key: str,
    ) -> OperationRecord:
        thread_hash, call_hash = _identity(thread_id, tool_call_id)
        candidate = OperationRecord(
            tool_name, action, request_fingerprint, permit_id, idempotency_key, "authorized"
        )
        _validate_record(
            candidate,
            tool_name=tool_name,
            action=action,
            request_fingerprint=request_fingerprint,
            idempotency_key=idempotency_key,
        )
        with self.pool.connection() as conn, conn.transaction():
            inserted = conn.execute(
                """
                INSERT INTO paca_langgraph.execution_journal
                    (thread_hash, tool_call_hash, tool_name, action,
                     request_fingerprint, permit_id, idempotency_key, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'authorized')
                ON CONFLICT (thread_hash, tool_call_hash) DO NOTHING
                RETURNING tool_name, action, request_fingerprint, permit_id,
                          idempotency_key, status, result_json, execution_id
                """,
                (
                    thread_hash, call_hash, tool_name, action,
                    request_fingerprint, UUID(permit_id), idempotency_key,
                ),
            ).fetchone()
            row = inserted or conn.execute(
                """
                SELECT tool_name, action, request_fingerprint, permit_id,
                       idempotency_key, status, result_json, execution_id
                FROM paca_langgraph.execution_journal
                WHERE thread_hash = %s AND tool_call_hash = %s
                FOR UPDATE
                """,
                (thread_hash, call_hash),
            ).fetchone()
        if row is None:
            raise OperationLedgerError("paca_execution_journal_write_missing")
        return _validate_record(
            self._row(row),
            tool_name=tool_name,
            action=action,
            request_fingerprint=request_fingerprint,
            idempotency_key=idempotency_key,
        )

    def claim_execution(
        self,
        *,
        thread_id: str,
        tool_call_id: str,
        tool_name: str,
        action: str,
        request_fingerprint: str,
        idempotency_key: str,
    ) -> ExecutionClaim:
        thread_hash, call_hash = _identity(thread_id, tool_call_id)
        token = str(uuid4())
        with self.pool.connection() as conn, conn.transaction():
            claimed = conn.execute(
                """
                UPDATE paca_langgraph.execution_journal
                SET lease_owner = %s,
                    lease_expires_at = now() + (%s * interval '1 second'),
                    updated_at = now()
                WHERE thread_hash = %s AND tool_call_hash = %s
                  AND tool_name = %s AND action = %s
                  AND request_fingerprint = %s AND idempotency_key = %s
                  AND status = 'authorized'
                  AND (lease_owner IS NULL OR lease_expires_at <= now())
                RETURNING tool_name, action, request_fingerprint, permit_id,
                          idempotency_key, status, result_json, execution_id
                """,
                (
                    UUID(token), self.claim_ttl_seconds, thread_hash, call_hash,
                    tool_name, action, request_fingerprint, idempotency_key,
                ),
            ).fetchone()
            if claimed:
                return ExecutionClaim(self._row(claimed), token)
            row = conn.execute(
                """
                SELECT tool_name, action, request_fingerprint, permit_id,
                       idempotency_key, status, result_json, execution_id,
                       lease_owner, lease_expires_at
                FROM paca_langgraph.execution_journal
                WHERE thread_hash = %s AND tool_call_hash = %s
                FOR UPDATE
                """,
                (thread_hash, call_hash),
            ).fetchone()
        if row is None:
            raise OperationLedgerError("paca_execution_journal_missing")
        record = _validate_record(
            self._row(row),
            tool_name=tool_name,
            action=action,
            request_fingerprint=request_fingerprint,
            idempotency_key=idempotency_key,
        )
        if record.status == "authorized" and row["lease_owner"] is not None:
            raise OperationInProgress("paca_operation_in_progress")
        if record.status == "authorized":
            raise OperationLedgerError("paca_execution_journal_claim_failed")
        return ExecutionClaim(record, None)

    def complete_execution(
        self,
        *,
        thread_id: str,
        tool_call_id: str,
        claim_token: str,
        status: str,
        result: dict[str, Any],
        execution_id: str | None,
    ) -> OperationRecord:
        if status not in {"succeeded", "failed", "unknown"}:
            raise ValueError("invalid_terminal_operation_status")
        try:
            json.dumps(result, allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise OperationLedgerError("paca_execution_journal_result_invalid") from exc
        thread_hash, call_hash = _identity(thread_id, tool_call_id)
        with self.pool.connection() as conn, conn.transaction():
            row = conn.execute(
                """
                UPDATE paca_langgraph.execution_journal
                SET status = %s, result_json = %s, execution_id = %s,
                    lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
                WHERE thread_hash = %s AND tool_call_hash = %s
                  AND lease_owner = %s AND status = 'authorized'
                RETURNING tool_name, action, request_fingerprint, permit_id,
                          idempotency_key, status, result_json, execution_id
                """,
                (
                    status, Jsonb(result), execution_id, thread_hash, call_hash, UUID(claim_token)
                ),
            ).fetchone()
        if row is None:
            raise OperationLedgerError("paca_execution_journal_lease_lost")
        return self._row(row)

    def release_execution(
        self, *, thread_id: str, tool_call_id: str, claim_token: str
    ) -> None:
        thread_hash, call_hash = _identity(thread_id, tool_call_id)
        with self.pool.connection() as conn, conn.transaction():
            conn.execute(
                """
                UPDATE paca_langgraph.execution_journal
                SET lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
                WHERE thread_hash = %s AND tool_call_hash = %s
                  AND lease_owner = %s AND status = 'authorized'
                """,
                (thread_hash, call_hash, UUID(claim_token)),
            )
