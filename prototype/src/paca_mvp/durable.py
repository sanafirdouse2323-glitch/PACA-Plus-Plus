"""Durable operation/idempotency store with an append-only hash-chained audit log.

SQLite is durable and coordinates callers sharing one local database file. For
multi-host deployments, use PostgresOperationStore. Neither store can make an
arbitrary external side effect exactly-once; uncertain outcomes become UNKNOWN
and must be reconciled instead of blindly retried.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterator
from uuid import uuid4

_ROOT_HASH = "0" * 64
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_TTL_SECONDS = 300.0
_MAX_RESULT_BYTES = 1_048_576


class StoreError(RuntimeError):
    """Base class for durable operation-state errors."""


class IdempotencyConflict(StoreError):
    """An idempotency key was reused with different request material."""


class OperationStateError(StoreError):
    """An operation is not in a state that permits the requested transition."""


class OperationOutcomeUnknown(StoreError):
    """An effect may have happened, but its final outcome cannot safely be inferred."""


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("value_must_be_finite_json") from exc


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


@dataclass(frozen=True)
class OperationRecord:
    operation_id: str
    idempotency_key: str
    request_fingerprint: str
    principal_id: str
    action: str
    resource: str
    arguments_digest: str
    context_digest: str
    policy_decision: dict[str, Any]
    status: str
    created_at: str
    expires_at: str
    started_at: str | None
    finished_at: str | None
    response: Any = None
    error_code: str | None = None


class _Session:
    def __init__(self, connection: Any, dialect: str):
        self.connection = connection
        self.dialect = dialect

    def execute(self, query: str, params: tuple[Any, ...] = ()):
        if self.dialect == "postgres":
            query = query.replace("?", "%s")
        return self.connection.execute(query, params)

    def one(self, query: str, params: tuple[Any, ...] = (), *, for_update: bool = False):
        if for_update and self.dialect == "postgres":
            query += " FOR UPDATE"
        return self.execute(query, params).fetchone()

    def all(self, query: str, params: tuple[Any, ...] = (), *, for_update: bool = False):
        if for_update and self.dialect == "postgres":
            query += " FOR UPDATE"
        return self.execute(query, params).fetchall()


class _BaseOperationStore:
    dialect = "abstract"

    @contextmanager
    def _transaction(self) -> Iterator[_Session]:
        raise NotImplementedError

    def _append_audit(
        self,
        session: _Session,
        event_type: str,
        operation_id: str | None,
        principal_id: str | None,
        payload: dict[str, Any],
    ) -> None:
        event_id = uuid4().hex
        event_time = _iso(utc_now())
        payload_json = canonical_json(payload)
        head = session.one("SELECT head_hash FROM audit_head WHERE singleton=1", for_update=True)
        if head is None:
            raise StoreError("audit_head_missing")
        previous_hash = head["head_hash"]
        event_material = {
            "event_id": event_id,
            "event_time": event_time,
            "event_type": event_type,
            "operation_id": operation_id,
            "principal_id": principal_id,
            "payload": json.loads(payload_json),
            "previous_hash": previous_hash,
        }
        entry_hash = canonical_digest(event_material)
        session.execute(
            """INSERT INTO audit_events
            (event_id,event_time,event_type,operation_id,principal_id,payload_json,previous_hash,entry_hash)
            VALUES (?,?,?,?,?,?,?,?)""",
            (event_id, event_time, event_type, operation_id, principal_id,
             payload_json, previous_hash, entry_hash),
        )
        session.execute("UPDATE audit_head SET head_hash=? WHERE singleton=1", (entry_hash,))

    @staticmethod
    def _record(row: Any) -> OperationRecord:
        return OperationRecord(
            operation_id=row["operation_id"],
            idempotency_key=row["idempotency_key"],
            request_fingerprint=row["request_fingerprint"],
            principal_id=row["principal_id"],
            action=row["action"],
            resource=row["resource"],
            arguments_digest=row["arguments_digest"],
            context_digest=row["context_digest"],
            policy_decision=json.loads(row["policy_decision_json"]),
            status=row["status"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            response=None if row["response_json"] is None else json.loads(row["response_json"]),
            error_code=row["error_code"],
        )

    def record_denial(self, principal_id: str | None, action: str, resource: str, reason: str) -> None:
        with self._transaction() as session:
            self._append_audit(session, "authorization_denied", None, principal_id,
                               {"action": action, "resource": resource, "reason": reason})

    def create_or_get(
        self,
        *,
        idempotency_key: str,
        principal_id: str,
        action: str,
        resource: str,
        arguments_digest: str,
        context_digest: str,
        policy_decision: dict[str, Any],
        ttl_seconds: float = 30.0,
    ) -> tuple[OperationRecord, bool]:
        if not isinstance(idempotency_key, str) or not _IDEMPOTENCY_RE.fullmatch(idempotency_key):
            raise ValueError("idempotency_key must be 1-128 safe ASCII characters")
        if not isinstance(principal_id, str) or not principal_id.strip():
            raise ValueError("principal_id is required")
        if not isinstance(action, str) or not action.strip():
            raise ValueError("action is required")
        if not isinstance(resource, str) or not resource.strip():
            raise ValueError("resource is required")
        try:
            valid_ttl = (not isinstance(ttl_seconds, bool)
                         and isinstance(ttl_seconds, (int, float))
                         and math.isfinite(float(ttl_seconds))
                         and 0 < ttl_seconds <= _MAX_TTL_SECONDS)
        except (OverflowError, TypeError, ValueError):
            valid_ttl = False
        if not valid_ttl:
            raise ValueError("ttl_seconds must be finite, positive, and at most 300")
        # Only digests and the policy reason are stored; raw tool arguments/context are not logged.
        policy_json = canonical_json(policy_decision)
        fingerprint = canonical_digest({
            "principal_id": principal_id, "action": action, "resource": resource,
            "arguments_digest": arguments_digest, "context_digest": context_digest,
        })
        operation_id = uuid4().hex
        created_at = _iso(utc_now())
        expires_at = _iso(utc_now() + timedelta(seconds=float(ttl_seconds)))
        conflict = False
        created = False
        result_row = None
        with self._transaction() as session:
            existing = session.one(
                "SELECT * FROM operations WHERE idempotency_key=?", (idempotency_key,), for_update=True
            )
            if existing is None:
                session.execute(
                    """INSERT INTO operations
                    (operation_id,idempotency_key,request_fingerprint,principal_id,action,resource,
                     arguments_digest,context_digest,policy_decision_json,status,created_at,expires_at,
                     started_at,finished_at,response_json,error_code)
                    VALUES (?,?,?,?,?,?,?,?,?,'issued',?,?,NULL,NULL,NULL,NULL)
                    ON CONFLICT (idempotency_key) DO NOTHING""",
                    (operation_id, idempotency_key, fingerprint, principal_id, action, resource,
                     arguments_digest, context_digest, policy_json, created_at, expires_at),
                )
                result_row = session.one(
                    "SELECT * FROM operations WHERE idempotency_key=?", (idempotency_key,), for_update=True
                )
                created = result_row["operation_id"] == operation_id
            else:
                result_row = existing
            if result_row is None:
                raise StoreError("operation_insert_or_lookup_failed")
            if result_row["request_fingerprint"] != fingerprint:
                conflict = True
                self._append_audit(session, "idempotency_conflict", result_row["operation_id"],
                                   principal_id, {"action": action, "resource": resource})
            elif created:
                self._append_audit(session, "authorization_allowed", operation_id, principal_id, {
                    "action": action, "resource": resource, "arguments_digest": arguments_digest,
                    "context_digest": context_digest, "decision": json.loads(policy_json),
                })
            else:
                self._append_audit(session, "idempotency_replay", result_row["operation_id"],
                                   principal_id, {"action": action, "resource": resource,
                                                  "existing_status": result_row["status"]})
        if conflict:
            raise IdempotencyConflict("idempotency_key_reused_for_different_operation")
        return self._record(result_row), created

    def claim(self, operation_id: str) -> OperationRecord:
        error: str | None = None
        row = None
        with self._transaction() as session:
            row = session.one("SELECT * FROM operations WHERE operation_id=?",
                              (operation_id,), for_update=True)
            if row is None:
                error = "operation_not_found"
            elif row["status"] != "issued":
                status = row["status"]
                error = {
                    "in_progress": "operation_in_progress",
                    "succeeded": "operation_already_completed",
                    "unknown": "operation_outcome_unknown",
                    "expired": "operation_expired",
                    "cancelled": "operation_cancelled",
                    "failed": "operation_failed",
                }.get(status, "operation_not_executable")
            elif row["expires_at"] <= _iso(utc_now()):
                session.execute("UPDATE operations SET status='expired',finished_at=?,error_code=? WHERE operation_id=?",
                                (_iso(utc_now()), "permit_expired", operation_id))
                self._append_audit(session, "operation_expired", operation_id, row["principal_id"], {})
                error = "operation_expired"
            else:
                started_at = _iso(utc_now())
                session.execute("UPDATE operations SET status='in_progress',started_at=? WHERE operation_id=? AND status='issued'",
                                (started_at, operation_id))
                self._append_audit(session, "effect_dispatch_started", operation_id, row["principal_id"], {
                    "action": row["action"], "resource": row["resource"]
                })
                row = session.one("SELECT * FROM operations WHERE operation_id=?", (operation_id,))
        if error:
            if error == "operation_outcome_unknown":
                raise OperationOutcomeUnknown(error)
            raise OperationStateError(error)
        return self._record(row)

    def complete(self, operation_id: str, response: Any) -> OperationRecord:
        response_json = canonical_json(response)
        if len(response_json.encode("utf-8")) > _MAX_RESULT_BYTES:
            raise ValueError("effect_result_exceeds_1MiB")
        with self._transaction() as session:
            row = session.one("SELECT * FROM operations WHERE operation_id=?", (operation_id,), for_update=True)
            if row is None:
                raise StoreError("operation_not_found")
            if row["status"] != "in_progress":
                raise OperationStateError("operation_not_in_progress")
            finished_at = _iso(utc_now())
            session.execute(
                "UPDATE operations SET status='succeeded',finished_at=?,response_json=?,error_code=NULL WHERE operation_id=?",
                (finished_at, response_json, operation_id),
            )
            self._append_audit(session, "effect_completed", operation_id, row["principal_id"], {
                "action": row["action"], "resource": row["resource"],
                "response_digest": canonical_digest(response),
            })
            updated = session.one("SELECT * FROM operations WHERE operation_id=?", (operation_id,))
        return self._record(updated)

    def mark_unknown(self, operation_id: str, error_code: str) -> None:
        safe_error = re.sub(r"[^A-Za-z0-9_.:-]", "_", str(error_code))[:120] or "effect_outcome_unknown"
        with self._transaction() as session:
            row = session.one("SELECT * FROM operations WHERE operation_id=?", (operation_id,), for_update=True)
            if row is None or row["status"] not in {"in_progress", "issued"}:
                return
            session.execute(
                "UPDATE operations SET status='unknown',finished_at=?,error_code=? WHERE operation_id=?",
                (_iso(utc_now()), safe_error, operation_id),
            )
            self._append_audit(session, "effect_outcome_unknown", operation_id, row["principal_id"],
                               {"error_code": safe_error, "action": row["action"], "resource": row["resource"]})

    def cancel_issued(self, operation_id: str, reason: str) -> None:
        safe_reason = re.sub(r"[^A-Za-z0-9_.:-]", "_", str(reason))[:120] or "operation_cancelled"
        with self._transaction() as session:
            row = session.one("SELECT * FROM operations WHERE operation_id=?", (operation_id,), for_update=True)
            if row is None or row["status"] != "issued":
                return
            session.execute(
                "UPDATE operations SET status='cancelled',finished_at=?,error_code=? WHERE operation_id=?",
                (_iso(utc_now()), safe_reason, operation_id),
            )
            self._append_audit(session, "operation_cancelled", operation_id, row["principal_id"],
                               {"reason": safe_reason})

    def get_operation(self, operation_id: str) -> OperationRecord | None:
        with self._transaction() as session:
            row = session.one("SELECT * FROM operations WHERE operation_id=?", (operation_id,))
        return None if row is None else self._record(row)

    def reconcile_unknown(
        self, operation_id: str, *, outcome: str, reason: str, response: Any = None,
    ) -> OperationRecord:
        """Privileged operator action for a separately verified external outcome.

        Never call this merely because a timeout occurred. The operator must establish
        the downstream result using that system's authoritative record.
        """
        if outcome not in {"succeeded", "failed"}:
            raise ValueError("outcome must be 'succeeded' or 'failed'")
        safe_reason = re.sub(r"[^A-Za-z0-9_.:-]", "_", str(reason))[:120] or "operator_reconciliation"
        response_json = None
        if outcome == "succeeded":
            response_json = canonical_json(response)
            if len(response_json.encode("utf-8")) > _MAX_RESULT_BYTES:
                raise ValueError("effect_result_exceeds_1MiB")
        updated = None
        with self._transaction() as session:
            row = session.one("SELECT * FROM operations WHERE operation_id=?", (operation_id,), for_update=True)
            if row is None:
                raise StoreError("operation_not_found")
            if row["status"] != "unknown":
                raise OperationStateError("only_unknown_operations_can_be_reconciled")
            finished_at = _iso(utc_now())
            session.execute(
                "UPDATE operations SET status=?,finished_at=?,response_json=?,error_code=? WHERE operation_id=?",
                (outcome, finished_at, response_json,
                 None if outcome == "succeeded" else "reconciled_failed", operation_id),
            )
            self._append_audit(session, "operator_reconciliation", operation_id, row["principal_id"], {
                "outcome": outcome, "reason": safe_reason,
                "response_digest": canonical_digest(response) if outcome == "succeeded" else None,
            })
            updated = session.one("SELECT * FROM operations WHERE operation_id=?", (operation_id,))
        return self._record(updated)

    def recover_incomplete(self, older_than_seconds: float = 60.0) -> int:
        if not math.isfinite(older_than_seconds) or older_than_seconds <= 0:
            raise ValueError("older_than_seconds must be positive and finite")
        cutoff = _iso(utc_now() - timedelta(seconds=older_than_seconds))
        recovered = 0
        with self._transaction() as session:
            rows = session.all(
                "SELECT * FROM operations WHERE status='in_progress' AND started_at < ?",
                (cutoff,), for_update=True,
            )
            for row in rows:
                session.execute(
                    "UPDATE operations SET status='unknown',finished_at=?,error_code=? WHERE operation_id=? AND status='in_progress'",
                    (_iso(utc_now()), "recovered_after_interruption", row["operation_id"]),
                )
                self._append_audit(session, "effect_recovered_as_unknown", row["operation_id"],
                                   row["principal_id"], {"reason": "process_interruption"})
                recovered += 1
        return recovered

    def verify_audit_chain(self) -> bool:
        with self._transaction() as session:
            # Lock the audit head first so concurrent appends cannot make this read
            # observe events and a head value from different database snapshots.
            head = session.one("SELECT head_hash FROM audit_head WHERE singleton=1", for_update=True)
            rows = session.all("SELECT * FROM audit_events ORDER BY seq ASC")
        previous = _ROOT_HASH
        for row in rows:
            material = {
                "event_id": row["event_id"],
                "event_time": row["event_time"],
                "event_type": row["event_type"],
                "operation_id": row["operation_id"],
                "principal_id": row["principal_id"],
                "payload": json.loads(row["payload_json"]),
                "previous_hash": previous,
            }
            calculated = canonical_digest(material)
            if row["previous_hash"] != previous or row["entry_hash"] != calculated:
                return False
            previous = calculated
        return head is not None and head["head_hash"] == previous


class SQLiteOperationStore(_BaseOperationStore):
    """Durable store for one host or several processes sharing one SQLite database file."""

    dialect = "sqlite"

    def __init__(self, path: str | os.PathLike[str]):
        self.path = str(Path(path).expanduser())
        if self.path == ":memory:":
            raise ValueError("Use a file-backed database so operation state is durable")
        Path(self.path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=15000")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript("""
            CREATE TABLE IF NOT EXISTS operations (
                operation_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                request_fingerprint TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                arguments_digest TEXT NOT NULL,
                context_digest TEXT NOT NULL,
                policy_decision_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('issued','in_progress','succeeded','unknown','failed','cancelled','expired')),
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                response_json TEXT,
                error_code TEXT
            );
            CREATE INDEX IF NOT EXISTS operations_status_started ON operations(status, started_at);
            CREATE TABLE IF NOT EXISTS audit_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                event_time TEXT NOT NULL,
                event_type TEXT NOT NULL,
                operation_id TEXT,
                principal_id TEXT,
                payload_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_head (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                head_hash TEXT NOT NULL
            );
            INSERT OR IGNORE INTO audit_head(singleton,head_hash) VALUES(1,'0000000000000000000000000000000000000000000000000000000000000000');
            """)

    @contextmanager
    def _transaction(self) -> Iterator[_Session]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield _Session(connection, "sqlite")
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()


class PostgresOperationStore(_BaseOperationStore):
    """Multi-instance durable store using PostgreSQL row locks and unique idempotency keys."""

    dialect = "postgres"

    def __init__(self, dsn: str):
        if not isinstance(dsn, str) or not dsn.strip():
            raise ValueError("PostgreSQL DSN is required")
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError("Install the production extra for PostgreSQL support") from exc
        self._psycopg = psycopg
        self._dict_row = dict_row
        self.dsn = dsn
        self._initialize()

    def _connect(self):
        return self._psycopg.connect(self.dsn, row_factory=self._dict_row, connect_timeout=5)

    def _initialize(self) -> None:
        with self._connect() as connection:
            session = _Session(connection, "postgres")
            session.execute("""
                CREATE TABLE IF NOT EXISTS operations (
                    operation_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    request_fingerprint TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    arguments_digest TEXT NOT NULL,
                    context_digest TEXT NOT NULL,
                    policy_decision_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('issued','in_progress','succeeded','unknown','failed','cancelled','expired')),
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    response_json TEXT,
                    error_code TEXT
                )
            """)
            session.execute("CREATE INDEX IF NOT EXISTS operations_status_started ON operations(status, started_at)")
            session.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    seq BIGSERIAL PRIMARY KEY,
                    event_id TEXT NOT NULL UNIQUE,
                    event_time TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    operation_id TEXT,
                    principal_id TEXT,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL
                )
            """)
            session.execute("""
                CREATE TABLE IF NOT EXISTS audit_head (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    head_hash TEXT NOT NULL
                )
            """)
            session.execute(
                "INSERT INTO audit_head(singleton,head_hash) VALUES(1,?) ON CONFLICT (singleton) DO NOTHING",
                (_ROOT_HASH,),
            )

    @contextmanager
    def _transaction(self) -> Iterator[_Session]:
        connection = self._connect()
        try:
            with connection:
                yield _Session(connection, "postgres")
        finally:
            connection.close()
