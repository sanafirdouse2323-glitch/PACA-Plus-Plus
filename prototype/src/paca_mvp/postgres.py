"""PostgreSQL-backed shared permit, idempotency and audit store.

Use this adapter when more than one host/replica must coordinate protected
operations. It relies on PostgreSQL row locks and transactions; downstream
remote effects still require idempotency/reconciliation because a database
cannot atomically commit a third-party side effect.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping
from hashlib import sha256
import json
import uuid

from .hardening import (
    EffectOutcomeUnknown, IdempotencyConflict, PermitRejected,
    _canonical_json, _digest, _validate_identifier,
)


class PostgresPermitStore:
    """Durable multi-host store compatible with GuardedGateway's store interface.

    The DSN, database role and network policy must be deployment-controlled.
    The supplied role needs table-creation permissions during initialization;
    for a locked-down deployment, provision the documented schema with a
    migration role and grant runtime access separately.
    """
    def __init__(self, dsn: str, connect_timeout: int = 5):
        if not isinstance(dsn, str) or not dsn.startswith(("postgresql://", "postgres://")):
            raise ValueError("dsn must be a PostgreSQL connection URL")
        if connect_timeout < 1 or connect_timeout > 120:
            raise ValueError("connect_timeout must be between 1 and 120 seconds")
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError(
                "PostgresPermitStore requires psycopg 3; install the project dependencies"
            ) from exc
        self.dsn = dsn
        self.connect_timeout = connect_timeout
        self._psycopg = psycopg
        self._dict_row = dict_row
        with self._connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS paca_permits (
                    permit_id TEXT PRIMARY KEY,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    actor_json JSONB,
                    policy_version TEXT NOT NULL,
                    state_version BIGINT NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    status TEXT NOT NULL CHECK(status IN
                        ('issued','executing','completed','failed','unknown','rejected')),
                    idempotency_key TEXT,
                    result_json JSONB,
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS paca_idempotency (
                    idempotency_key TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL,
                    permit_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_json JSONB,
                    updated_at TIMESTAMPTZ NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS paca_state (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    state_version BIGINT NOT NULL
                )
            """)
            db.execute("INSERT INTO paca_state(singleton,state_version) VALUES(1,0) ON CONFLICT(singleton) DO NOTHING")
            db.execute("""
                CREATE TABLE IF NOT EXISTS paca_audit (
                    sequence BIGSERIAL PRIMARY KEY,
                    event_id TEXT NOT NULL UNIQUE,
                    created_at TIMESTAMPTZ NOT NULL,
                    event TEXT NOT NULL,
                    permit_id TEXT,
                    action TEXT,
                    resource TEXT,
                    details_json JSONB NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS paca_audit_head (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    event_hash TEXT NOT NULL
                )
            """)
            db.execute("INSERT INTO paca_audit_head(singleton,event_hash) VALUES(1,%s) ON CONFLICT(singleton) DO NOTHING",
                       ("0" * 64,))

    def _connect(self):
        return self._psycopg.connect(
            self.dsn, connect_timeout=self.connect_timeout, row_factory=self._dict_row
        )

    def _audit(self, db, event: str, permit_id: str | None,
               action: str | None, resource: str | None,
               details: Mapping[str, Any]) -> None:
        head = db.execute(
            "SELECT event_hash FROM paca_audit_head WHERE singleton=1 FOR UPDATE"
        ).fetchone()
        previous_hash = head["event_hash"]
        event_id = uuid.uuid4().hex
        created_at = datetime.now(timezone.utc)
        detail_dict = dict(details)
        content = {
            "event_id": event_id, "created_at": created_at.isoformat(),
            "event": event, "permit_id": permit_id, "action": action,
            "resource": resource, "details": detail_dict,
            "previous_hash": previous_hash,
        }
        event_hash = _digest(content)
        db.execute("""
            INSERT INTO paca_audit
                (event_id,created_at,event,permit_id,action,resource,details_json,previous_hash,event_hash)
            VALUES(%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)
        """, (event_id, created_at, event, permit_id, action, resource,
              _canonical_json(detail_dict), previous_hash, event_hash))
        db.execute("UPDATE paca_audit_head SET event_hash=%s WHERE singleton=1", (event_hash,))

    def record_event(self, event: str, permit_id: str | None,
                     action: str | None, resource: str | None,
                     details: Mapping[str, Any]) -> None:
        with self._connect() as db:
            self._audit(db, event, permit_id, action, resource, details)

    def audit_events(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM paca_audit ORDER BY sequence").fetchall()
        return [{**row, "details": row["details_json"]} for row in rows]

    def verify_audit_chain(self) -> bool:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM paca_audit ORDER BY sequence").fetchall()
        previous_hash = "0" * 64
        for row in rows:
            created_at = row["created_at"].astimezone(timezone.utc).isoformat()
            content = {
                "event_id": row["event_id"], "created_at": created_at,
                "event": row["event"], "permit_id": row["permit_id"],
                "action": row["action"], "resource": row["resource"],
                "details": row["details_json"], "previous_hash": row["previous_hash"],
            }
            if row["previous_hash"] != previous_hash or _digest(content) != row["event_hash"]:
                return False
            previous_hash = row["event_hash"]
        return True

    def current_state_version(self) -> int:
        with self._connect() as db:
            row = db.execute("SELECT state_version FROM paca_state WHERE singleton=1").fetchone()
        return int(row["state_version"])

    def advance_state(self) -> int:
        with self._connect() as db:
            row = db.execute(
                "UPDATE paca_state SET state_version=state_version+1 WHERE singleton=1 RETURNING state_version"
            ).fetchone()
            version = int(row["state_version"])
            self._audit(db, "state_advanced", None, None, None, {"state_version": version})
            return version

    def issue(self, action: str, resource: str, request_hash: str, policy_version: str,
              ttl_seconds: float = 30.0, idempotency_key: str | None = None,
              actor: Mapping[str, Any] | None = None) -> str:
        _validate_identifier(action, "action")
        _validate_identifier(resource, "resource")
        _validate_identifier(policy_version, "policy_version")
        if ttl_seconds <= 0 or ttl_seconds > 3600:
            raise ValueError("ttl_seconds must be in (0, 3600]")
        if idempotency_key is not None:
            _validate_identifier(idempotency_key, "idempotency_key")
        actor_json = _canonical_json(dict(actor)) if actor is not None else None
        now = datetime.now(timezone.utc)
        permit_id = uuid.uuid4().hex
        with self._connect() as db:
            if idempotency_key:
                prior = db.execute(
                    "SELECT * FROM paca_idempotency WHERE idempotency_key=%s FOR UPDATE",
                    (idempotency_key,),
                ).fetchone()
                if prior:
                    if prior["request_hash"] != request_hash:
                        raise IdempotencyConflict("idempotency key reused for a different request")
                    if prior["status"] == "completed":
                        return prior["permit_id"]
                    if prior["status"] == "issued":
                        old = db.execute(
                            "SELECT status,expires_at FROM paca_permits WHERE permit_id=%s FOR UPDATE",
                            (prior["permit_id"],),
                        ).fetchone()
                        if old and old["status"] == "issued" and now < old["expires_at"]:
                            return prior["permit_id"]
                        raise PermitRejected("idempotency key refers to an expired or terminal permit")
                    if prior["status"] in {"executing", "unknown"}:
                        raise EffectOutcomeUnknown("previous operation may have reached the downstream system")
                    raise PermitRejected("idempotency key refers to a terminal failed operation")
            state_row = db.execute(
                "SELECT state_version FROM paca_state WHERE singleton=1"
            ).fetchone()
            state_version = int(state_row["state_version"])
            expires_at = now + timedelta(seconds=ttl_seconds)
            db.execute("""
                INSERT INTO paca_permits
                    (permit_id,action,resource,request_hash,actor_json,policy_version,state_version,
                     expires_at,status,idempotency_key,result_json,created_at,updated_at)
                VALUES(%s,%s,%s,%s,%s::jsonb,%s,%s,%s,'issued',%s,NULL,%s,%s)
            """, (permit_id, action, resource, request_hash, actor_json, policy_version,
                  state_version, expires_at, idempotency_key, now, now))
            if idempotency_key:
                db.execute("""
                    INSERT INTO paca_idempotency
                        (idempotency_key,request_hash,permit_id,status,result_json,updated_at)
                    VALUES(%s,%s,%s,'issued',NULL,%s)
                """, (idempotency_key, request_hash, permit_id, now))
            self._audit(db, "permit_issued", permit_id, action, resource, {
                "request_hash": request_hash, "actor": dict(actor) if actor is not None else None,
                "policy_version": policy_version, "state_version": state_version,
                "expires_at": expires_at.isoformat(),
                "idempotency_key_hash": _digest(idempotency_key) if idempotency_key else None,
            })
            return permit_id

    def execute(self, permit_id: str, action: str, resource: str, request_hash: str,
                current_policy_version: str, effect: Callable[[], Any],
                idempotency_key: str | None = None,
                pre_effect_check: Callable[[], None] | None = None) -> Any:
        now = datetime.now(timezone.utc)
        # Phase 1 durably claims the permit. If phase 2 crashes, this claim survives.
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM paca_permits WHERE permit_id=%s FOR UPDATE", (permit_id,)
            ).fetchone()
            if row is None:
                raise PermitRejected("unknown permit")
            actor = row["actor_json"]
            if row["action"] != action or row["resource"] != resource:
                self._audit(db, "permit_rejected", permit_id, action, resource,
                            {"reason": "action_or_resource_mismatch", "actor": actor})
                db.commit()
                raise PermitRejected("action or resource mismatch")
            if row["request_hash"] != request_hash:
                raise PermitRejected("request payload mismatch")
            if row["idempotency_key"] != idempotency_key:
                raise PermitRejected("idempotency key mismatch")
            if row["status"] == "completed":
                return row["result_json"]
            if row["status"] in {"executing", "unknown"}:
                raise EffectOutcomeUnknown("operation was claimed earlier; reconcile downstream state")
            if row["status"] != "issued":
                raise PermitRejected("permit is not executable")
            state_row = db.execute(
                "SELECT state_version FROM paca_state WHERE singleton=1"
            ).fetchone()
            state_version = int(state_row["state_version"])
            rejection = None
            if now >= row["expires_at"]:
                rejection = "expired"
            elif row["state_version"] != state_version:
                rejection = "stale_state"
            elif row["policy_version"] != current_policy_version:
                rejection = "stale_policy"
            if rejection:
                db.execute("UPDATE paca_permits SET status='rejected',updated_at=%s WHERE permit_id=%s",
                           (now, permit_id))
                if idempotency_key:
                    db.execute("UPDATE paca_idempotency SET status='rejected',updated_at=%s WHERE idempotency_key=%s",
                               (now, idempotency_key))
                self._audit(db, "permit_rejected", permit_id, action, resource,
                            {"reason": rejection, "actor": actor})
                db.commit()
                raise PermitRejected(rejection.replace("_", " "))
            db.execute("UPDATE paca_permits SET status='executing',updated_at=%s WHERE permit_id=%s",
                       (now, permit_id))
            if idempotency_key:
                db.execute("UPDATE paca_idempotency SET status='executing',updated_at=%s WHERE idempotency_key=%s",
                           (now, idempotency_key))
            self._audit(db, "effect_claimed", permit_id, action, resource, {
                "actor": actor, "state_version": state_version,
                "policy_version": current_policy_version,
            })
        # Phase 2: shared-read lock on state prevents a concurrent state update from
        # committing until the effect/result/audit transaction has completed. Multiple
        # effects can run concurrently because they only share-lock this one row.
        effect_started = False
        try:
            with self._connect() as db:
                row = db.execute(
                    "SELECT * FROM paca_permits WHERE permit_id=%s FOR UPDATE", (permit_id,)
                ).fetchone()
                if row is None or row["status"] != "executing":
                    raise EffectOutcomeUnknown("execution claim is no longer active")
                actor = row["actor_json"]
                state_row = db.execute(
                    "SELECT state_version FROM paca_state WHERE singleton=1 FOR SHARE"
                ).fetchone()
                state_version = int(state_row["state_version"])
                now = datetime.now(timezone.utc)
                rejection = None
                if now >= row["expires_at"]:
                    rejection = "expired"
                elif row["state_version"] != state_version:
                    rejection = "stale_state"
                elif row["policy_version"] != current_policy_version:
                    rejection = "stale_policy"
                if rejection:
                    db.execute("UPDATE paca_permits SET status='rejected',updated_at=%s WHERE permit_id=%s",
                               (now, permit_id))
                    if idempotency_key:
                        db.execute("UPDATE paca_idempotency SET status='rejected',updated_at=%s WHERE idempotency_key=%s",
                                   (now, idempotency_key))
                    self._audit(db, "permit_rejected", permit_id, action, resource,
                                {"reason": rejection, "actor": actor})
                    db.commit()
                    raise PermitRejected(rejection.replace("_", " "))
                if pre_effect_check is not None:
                    try:
                        pre_effect_check()
                    except Exception as exc:
                        db.execute("UPDATE paca_permits SET status='rejected',updated_at=%s WHERE permit_id=%s",
                                   (datetime.now(timezone.utc), permit_id))
                        if idempotency_key:
                            db.execute("UPDATE paca_idempotency SET status='rejected',updated_at=%s WHERE idempotency_key=%s",
                                       (datetime.now(timezone.utc), idempotency_key))
                        self._audit(db, "permit_rejected", permit_id, action, resource,
                                    {"reason": "pre_effect_check_failed", "actor": actor,
                                     "exception_type": type(exc).__name__})
                        db.commit()
                        if isinstance(exc, PermitRejected):
                            raise
                        raise PermitRejected("pre-effect validation failed; no effect was invoked") from exc

                effect_started = True
                try:
                    result = effect()
                    serialized = _canonical_json(result)
                except Exception as exc:
                    db.execute("UPDATE paca_permits SET status='unknown',updated_at=%s WHERE permit_id=%s",
                               (datetime.now(timezone.utc), permit_id))
                    if idempotency_key:
                        db.execute("UPDATE paca_idempotency SET status='unknown',updated_at=%s WHERE idempotency_key=%s",
                                   (datetime.now(timezone.utc), idempotency_key))
                    self._audit(db, "effect_outcome_unknown", permit_id, action, resource,
                                {"actor": actor, "exception_type": type(exc).__name__})
                    db.commit()
                    raise EffectOutcomeUnknown(
                        "effect raised or result was not serializable; downstream state must be reconciled"
                    ) from exc
                db.execute("UPDATE paca_permits SET status='completed',result_json=%s::jsonb,updated_at=%s WHERE permit_id=%s",
                           (serialized, datetime.now(timezone.utc), permit_id))
                if idempotency_key:
                    db.execute("UPDATE paca_idempotency SET status='completed',result_json=%s::jsonb,updated_at=%s WHERE idempotency_key=%s",
                               (serialized, datetime.now(timezone.utc), idempotency_key))
                self._audit(db, "effect_completed", permit_id, action, resource,
                            {"actor": actor, "result_hash": _digest(result)})
                return result
        except EffectOutcomeUnknown:
            raise
        except Exception as exc:
            if effect_started:
                raise EffectOutcomeUnknown(
                    "effect may have succeeded but durable completion could not be confirmed"
                ) from exc
            raise

    def mark_unknown_operations_for_reconciliation(self) -> int:
        with self._connect() as db:
            rows = db.execute("""
                SELECT permit_id,action,resource,idempotency_key,actor_json
                FROM paca_permits WHERE status='executing' FOR UPDATE
            """).fetchall()
            for row in rows:
                db.execute("UPDATE paca_permits SET status='unknown',updated_at=%s WHERE permit_id=%s",
                           (datetime.now(timezone.utc), row["permit_id"]))
                if row["idempotency_key"]:
                    db.execute("UPDATE paca_idempotency SET status='unknown',updated_at=%s WHERE idempotency_key=%s",
                               (datetime.now(timezone.utc), row["idempotency_key"]))
                self._audit(db, "crash_recovery_unknown", row["permit_id"], row["action"],
                            row["resource"], {"actor": row["actor_json"],
                                              "note": "reconcile downstream before retry"})
            return len(rows)
