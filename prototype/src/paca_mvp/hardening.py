"""Hardening primitives for PACA++.

This module is a research integration layer, not a turnkey production service.
It provides an OPA REST decision client, explicit trusted-context interfaces,
SQLite-coordinated permit/idempotency/audit state, and fail-closed effect
execution. Real remote effects cannot be made atomic with SQLite: adapters
must use downstream idempotency or transactional APIs for recovery.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler
from urllib.parse import urlparse
import json
import os
import sqlite3
import uuid


class HardeningError(RuntimeError):
    """Base error for hardening integration failures."""


class PolicyUnavailable(HardeningError):
    """Policy decision point failed or returned an invalid decision."""


class ContextUnavailable(HardeningError):
    """Trusted identity/authorization context could not be established."""


class PermitRejected(HardeningError):
    """A durable execution permit is absent, stale, consumed, or invalid."""


class IdempotencyConflict(HardeningError):
    """An idempotency key was reused for a different operation."""


class EffectOutcomeUnknown(HardeningError):
    """A prior remote operation was claimed but its result cannot be recovered."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _urlopen_no_redirect(request: Request, timeout: float):
    """Do not forward credentials or protected payloads across HTTP redirects."""
    return build_opener(_NoRedirectHandler()).open(request, timeout=timeout)


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _digest(value: Any) -> str:
    return sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _validate_identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise ValueError(f"{label} must be a non-empty string of at most 512 characters")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError(f"{label} must not contain control characters")
    return value


@dataclass(frozen=True)
class TrustedPrincipal:
    """Identity claims created only by a verified authentication/context adapter.

    Callers must not build this from untrusted request JSON. Production adapters
    should verify issuer, audience, signature, expiry, tenant and revocation, or
    fetch context from a trusted source. This dataclass itself is not proof of
    identity.
    """
    subject: str
    issuer: str
    audience: str
    claims: Mapping[str, Any]
    authenticated_at: str

    def to_context(self) -> dict[str, Any]:
        for value, label in ((self.subject, "subject"), (self.issuer, "issuer"),
                             (self.audience, "audience")):
            _validate_identifier(value, label)
        return {
            "identity": {
                "subject": self.subject,
                "issuer": self.issuer,
                "audience": self.audience,
                "authenticated_at": self.authenticated_at,
                "claims": dict(self.claims),
            }
        }


class IdentityProvider(Protocol):
    def authenticate(self, credential: str) -> TrustedPrincipal:
        """Validate a credential and return verified claims; never trust decoded-only JWTs."""


class AuthorizationContextProvider(Protocol):
    def get_context(self, principal: TrustedPrincipal,
                    action: str, resource: str) -> Mapping[str, Any]:
        """Fetch resource/tenant/session/risk attributes from trusted sources."""


class OPAClient:
    """Fail-closed client for a named OPA Data API decision.

    Expected Rego decision shape: {"allow": true|false, "policy_version": "...",
    "reason": "..."}; missing allow, malformed JSON, 404, timeout, non-2xx or
    connection errors raise PolicyUnavailable and must never turn into a permit.
    """
    def __init__(self, base_url: str, decision_path: str = "/v1/data/paca/authz/decision",
                 bearer_token: str | None = None, timeout_seconds: float = 2.0,
                 max_request_bytes: int = 1_048_576):
        parsed = urlparse(base_url)
        loopback_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not loopback_http:
            raise ValueError("OPA base_url must use HTTPS (HTTP is allowed only for loopback development)")
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("invalid OPA base_url")
        if not decision_path.startswith("/v1/data/") or ".." in decision_path:
            raise ValueError("decision_path must address an OPA /v1/data/ endpoint")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_request_bytes < 1:
            raise ValueError("max_request_bytes must be positive")
        self.base_url = base_url.rstrip("/")
        self.decision_path = decision_path
        self.bearer_token = bearer_token
        self.timeout_seconds = timeout_seconds
        self.max_request_bytes = max_request_bytes

    def get_policy_version(self) -> str:
        """Fetch the active version marker from OPA immediately before effect commit."""
        req = Request(self.base_url + "/v1/data/paca/authz/policy_version",
                      headers={"Accept": "application/json"}, method="GET")
        if self.bearer_token:
            req.add_header("Authorization", "Bearer " + self.bearer_token)
        try:
            with _urlopen_no_redirect(req, timeout=self.timeout_seconds) as response:
                if response.status != 200:
                    raise PolicyUnavailable(f"OPA version query returned HTTP {response.status}")
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise PolicyUnavailable("OPA version response exceeded 64 KiB")
            payload = json.loads(raw.decode("utf-8"))
            version = payload["result"]
            if not isinstance(version, str) or not version.strip():
                raise ValueError("policy version must be a non-empty string")
            return version
        except (HTTPError, URLError, TimeoutError, OSError, UnicodeDecodeError,
                json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise PolicyUnavailable("could not retrieve active OPA policy version") from exc

    def decide(self, request: Mapping[str, Any]) -> dict[str, Any]:
        try:
            body = _canonical_json({"input": dict(request)}).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise PolicyUnavailable("OPA input is not valid canonical JSON") from exc
        if len(body) > self.max_request_bytes:
            raise PolicyUnavailable("OPA input exceeded configured request limit")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.bearer_token:
            headers["Authorization"] = "Bearer " + self.bearer_token
        req = Request(self.base_url + self.decision_path, data=body,
                      headers=headers, method="POST")
        try:
            with _urlopen_no_redirect(req, timeout=self.timeout_seconds) as response:
                if response.status != 200:
                    raise PolicyUnavailable(f"OPA returned HTTP {response.status}")
                raw = response.read(1_048_577)
                if len(raw) > 1_048_576:
                    raise PolicyUnavailable("OPA response exceeded 1 MiB")
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise PolicyUnavailable("OPA decision request failed") from exc
        try:
            payload = json.loads(raw.decode("utf-8"))
            result = payload["result"]
            allow = result["allow"]
            if type(allow) is not bool:
                raise ValueError("allow is not a boolean")
            if allow:
                version = result.get("policy_version")
                if not isinstance(version, str) or not version.strip():
                    raise ValueError("permit decision is missing policy_version")
            return {"allowed": allow, "reason": str(result.get("reason", "opa_decision")),
                    "policy_version": result.get("policy_version"),
                    "decision_id": payload.get("decision_id")}
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise PolicyUnavailable("OPA response is missing a valid decision") from exc


class SQLitePermitStore:
    """Durable local permit, audit, and idempotency coordinator.

    SQLite coordinates processes sharing the same database file on a single
    machine/filesystem. It is not a distributed database and should not be placed
    on an arbitrary network filesystem. Use PostgreSQL or another transactional
    store for multi-host deployments.
    """
    def __init__(self, database_path: str, busy_timeout_ms: int = 5000):
        if database_path == ":memory:":
            raise ValueError("SQLitePermitStore requires a file-backed database for durable state")
        if busy_timeout_ms < 1 or busy_timeout_ms > 120000:
            raise ValueError("busy_timeout_ms must be between 1 and 120000")
        os.makedirs(os.path.dirname(os.path.abspath(database_path)), exist_ok=True)
        self.database_path = database_path
        self.busy_timeout_ms = busy_timeout_ms
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS permits (
                    permit_id TEXT PRIMARY KEY,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    actor_json TEXT,
                    policy_version TEXT NOT NULL,
                    state_version INTEGER NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN
                        ('issued','executing','completed','failed','unknown','rejected')),
                    idempotency_key TEXT,
                    result_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS permits_idempotency_key
                    ON permits(idempotency_key);
                CREATE TABLE IF NOT EXISTS state (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    state_version INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO state(singleton, state_version) VALUES(1, 0);
                CREATE TABLE IF NOT EXISTS audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    event TEXT NOT NULL,
                    permit_id TEXT,
                    action TEXT,
                    resource TEXT,
                    details_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS idempotency (
                    idempotency_key TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL,
                    permit_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_json TEXT,
                    updated_at TEXT NOT NULL
                );
            """)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(permits)").fetchall()}
            if "actor_json" not in columns:
                db.execute("ALTER TABLE permits ADD COLUMN actor_json TEXT")
            db.execute("PRAGMA journal_mode=WAL")
            db.execute(f"PRAGMA busy_timeout={int(self.busy_timeout_ms)}")
        # Permit/audit rows can contain protected result data; keep the local
        # database and any already-created WAL sidecars accessible only to its owner.
        for filename in (self.database_path, self.database_path + "-wal", self.database_path + "-shm"):
            if os.path.exists(filename):
                os.chmod(filename, 0o600)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database_path, timeout=self.busy_timeout_ms / 1000,
                             isolation_level=None, factory=_ClosingConnection)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute(f"PRAGMA busy_timeout={int(self.busy_timeout_ms)}")
        return db

    def _audit(self, db: sqlite3.Connection, event: str, permit_id: str | None,
               action: str | None, resource: str | None, details: Mapping[str, Any]) -> None:
        previous = db.execute("SELECT event_hash FROM audit ORDER BY sequence DESC LIMIT 1").fetchone()
        previous_hash = previous["event_hash"] if previous else "0" * 64
        event_id, created_at = uuid.uuid4().hex, _utcnow()
        content = {
            "event_id": event_id, "created_at": created_at, "event": event,
            "permit_id": permit_id, "action": action, "resource": resource,
            "details": dict(details), "previous_hash": previous_hash,
        }
        event_hash = _digest(content)
        db.execute("""INSERT INTO audit
            (event_id,created_at,event,permit_id,action,resource,details_json,previous_hash,event_hash)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (event_id, created_at, event, permit_id, action, resource,
             _canonical_json(dict(details)), previous_hash, event_hash))

    def verify_audit_chain(self) -> bool:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM audit ORDER BY sequence").fetchall()
        previous_hash = "0" * 64
        for row in rows:
            content = {
                "event_id": row["event_id"], "created_at": row["created_at"],
                "event": row["event"], "permit_id": row["permit_id"],
                "action": row["action"], "resource": row["resource"],
                "details": json.loads(row["details_json"]),
                "previous_hash": row["previous_hash"],
            }
            if row["previous_hash"] != previous_hash or _digest(content) != row["event_hash"]:
                return False
            previous_hash = row["event_hash"]
        return True

    def audit_events(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM audit ORDER BY sequence").fetchall()
        return [{**dict(row), "details": json.loads(row["details_json"])} for row in rows]

    def current_state_version(self) -> int:
        with self._connect() as db:
            return int(db.execute("SELECT state_version FROM state WHERE singleton=1").fetchone()[0])

    def advance_state(self) -> int:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("UPDATE state SET state_version=state_version+1 WHERE singleton=1")
                version = int(db.execute(
                    "SELECT state_version FROM state WHERE singleton=1").fetchone()[0])
                self._audit(db, "state_advanced", None, None, None, {"state_version": version})
                db.commit()
                return version
            except Exception:
                db.rollback()
                raise

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
        permit_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                state_version = int(db.execute(
                    "SELECT state_version FROM state WHERE singleton=1").fetchone()[0])
                if idempotency_key:
                    prior = db.execute("SELECT * FROM idempotency WHERE idempotency_key=?",
                                       (idempotency_key,)).fetchone()
                    if prior:
                        if prior["request_hash"] != request_hash:
                            raise IdempotencyConflict("idempotency key reused for a different request")
                        if prior["status"] in {"issued", "completed"}:
                            db.commit()
                            return prior["permit_id"]
                        if prior["status"] in {"executing", "unknown"}:
                            raise EffectOutcomeUnknown("previous operation may have reached the downstream system")
                        # failed/rejected operations are not silently retried under the same key
                        raise PermitRejected("idempotency key refers to a terminal failed operation")
                db.execute("""INSERT INTO permits
                    (permit_id,action,resource,request_hash,actor_json,policy_version,state_version,expires_at,
                     status,idempotency_key,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,'issued',?,?,?)""",
                    (permit_id, action, resource, request_hash, actor_json, policy_version, state_version,
                     (now + timedelta(seconds=ttl_seconds)).isoformat(), idempotency_key,
                     now.isoformat(), now.isoformat()))
                if idempotency_key:
                    db.execute("""INSERT INTO idempotency
                        (idempotency_key,request_hash,permit_id,status,updated_at)
                        VALUES(?,?,?,'issued',?)""",
                        (idempotency_key, request_hash, permit_id, now.isoformat()))
                self._audit(db, "permit_issued", permit_id, action, resource, {
                    "request_hash": request_hash, "actor": dict(actor) if actor is not None else None,
                    "policy_version": policy_version,
                    "state_version": state_version, "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
                    "idempotency_key_hash": _digest(idempotency_key) if idempotency_key else None,
                })
                db.commit()
                return permit_id
            except Exception:
                db.rollback()
                raise

    def execute(self, permit_id: str, action: str, resource: str, request_hash: str,
                current_policy_version: str, effect: Callable[[], Any],
                idempotency_key: str | None = None) -> Any:
        """Execute at most once within this store's claim protocol.

        A remote side effect and SQLite commit are not one transaction. The store
        records 'executing' before invoking the callback. If the process crashes
        during that callback, replay raises EffectOutcomeUnknown instead of
        repeating a possibly completed effect. A downstream API idempotency key
        is the correct way to make retries recoverable.
        """
        now = datetime.now(timezone.utc)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT * FROM permits WHERE permit_id=?", (permit_id,)).fetchone()
                if row is None:
                    raise PermitRejected("unknown permit")
                actor = json.loads(row["actor_json"]) if row["actor_json"] else None
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
                    if row["result_json"] is None:
                        raise EffectOutcomeUnknown("completed result unavailable")
                    return json.loads(row["result_json"])
                if row["status"] in {"executing", "unknown"}:
                    raise EffectOutcomeUnknown("operation was claimed earlier; reconcile downstream state")
                if row["status"] != "issued":
                    raise PermitRejected("permit is not executable")
                if now >= datetime.fromisoformat(row["expires_at"]):
                    db.execute("UPDATE permits SET status='rejected',updated_at=? WHERE permit_id=?",
                               (now.isoformat(), permit_id))
                    if idempotency_key:
                        db.execute("UPDATE idempotency SET status='rejected',updated_at=? WHERE idempotency_key=?",
                                   (now.isoformat(), idempotency_key))
                    self._audit(db, "permit_rejected", permit_id, action, resource, {"reason": "expired", "actor": actor})
                    db.commit()
                    raise PermitRejected("permit expired")
                state_version = int(db.execute(
                    "SELECT state_version FROM state WHERE singleton=1").fetchone()[0])
                if row["state_version"] != state_version:
                    db.execute("UPDATE permits SET status='rejected',updated_at=? WHERE permit_id=?",
                               (now.isoformat(), permit_id))
                    if idempotency_key:
                        db.execute("UPDATE idempotency SET status='rejected',updated_at=? WHERE idempotency_key=?",
                                   (now.isoformat(), idempotency_key))
                    self._audit(db, "permit_rejected", permit_id, action, resource,
                                {"reason": "stale_state", "actor": actor,
                                 "issued_state_version": row["state_version"],
                                 "current_state_version": state_version})
                    db.commit()
                    raise PermitRejected("stale state")
                if row["policy_version"] != current_policy_version:
                    db.execute("UPDATE permits SET status='rejected',updated_at=? WHERE permit_id=?",
                               (now.isoformat(), permit_id))
                    if idempotency_key:
                        db.execute("UPDATE idempotency SET status='rejected',updated_at=? WHERE idempotency_key=?",
                                   (now.isoformat(), idempotency_key))
                    self._audit(db, "permit_rejected", permit_id, action, resource,
                                {"reason": "stale_policy", "actor": actor,
                                 "issued_policy_version": row["policy_version"],
                                 "current_policy_version": current_policy_version})
                    db.commit()
                    raise PermitRejected("stale policy")
                db.execute("UPDATE permits SET status='executing',updated_at=? WHERE permit_id=?",
                           (now.isoformat(), permit_id))
                if idempotency_key:
                    db.execute("UPDATE idempotency SET status='executing',updated_at=? WHERE idempotency_key=?",
                               (now.isoformat(), idempotency_key))
                self._audit(db, "effect_claimed", permit_id, action, resource, {
                    "actor": actor, "state_version": state_version,
                    "policy_version": current_policy_version,
                })
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise

        try:
            result = effect()
            serialized = _canonical_json(result)
        except Exception as exc:
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute("UPDATE permits SET status='unknown',updated_at=? WHERE permit_id=?",
                               (_utcnow(), permit_id))
                    if idempotency_key:
                        db.execute("UPDATE idempotency SET status='unknown',updated_at=? WHERE idempotency_key=?",
                                   (_utcnow(), idempotency_key))
                    self._audit(db, "effect_outcome_unknown", permit_id, action, resource,
                                {"actor": actor, "exception_type": type(exc).__name__})
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
            raise EffectOutcomeUnknown("effect raised; downstream state must be reconciled") from exc

        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("UPDATE permits SET status='completed',result_json=?,updated_at=? WHERE permit_id=?",
                           (serialized, _utcnow(), permit_id))
                if idempotency_key:
                    db.execute("""UPDATE idempotency SET status='completed',result_json=?,updated_at=?
                                  WHERE idempotency_key=?""",
                               (serialized, _utcnow(), idempotency_key))
                self._audit(db, "effect_completed", permit_id, action, resource,
                            {"actor": actor, "result_hash": _digest(result)})
                db.commit()
            except Exception:
                db.rollback()
                # The downstream operation may already have succeeded.
                raise EffectOutcomeUnknown("effect succeeded but durable completion could not be recorded")
        return result

    def mark_unknown_operations_for_reconciliation(self) -> int:
        """Mark durable 'executing' records left by a crash as unknown; never replay automatically."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                rows = db.execute("SELECT permit_id,action,resource,idempotency_key,actor_json FROM permits WHERE status='executing'").fetchall()
                for row in rows:
                    db.execute("UPDATE permits SET status='unknown',updated_at=? WHERE permit_id=?",
                               (_utcnow(), row["permit_id"]))
                    if row["idempotency_key"]:
                        db.execute("UPDATE idempotency SET status='unknown',updated_at=? WHERE idempotency_key=?",
                                   (_utcnow(), row["idempotency_key"]))
                    self._audit(db, "crash_recovery_unknown", row["permit_id"], row["action"],
                                row["resource"], {"actor": json.loads(row["actor_json"]) if row["actor_json"] else None,
                                                  "note": "reconcile downstream before retry"})
                db.commit()
                return len(rows)
            except Exception:
                db.rollback()
                raise


class ProtectedToolAdapter(Protocol):
    """Tool-specific boundary; implementations must validate/canonicalize arguments."""
    def invoke(self, action: str, resource: str, arguments: Mapping[str, Any],
               idempotency_key: str) -> Any:
        """Call the protected tool/API with downstream idempotency if supported."""


class GuardedGateway:
    """Composes trusted context, OPA decisions, durable permits, and adapters."""
    def __init__(self, opa: OPAClient, store: SQLitePermitStore,
                 identity_provider: IdentityProvider,
                 context_provider: AuthorizationContextProvider):
        self.opa, self.store = opa, store
        self.identity_provider, self.context_provider = identity_provider, context_provider

    def authorize_and_execute(self, credential: str, action: str, resource: str,
                              arguments: Mapping[str, Any], adapter: ProtectedToolAdapter,
                              idempotency_key: str) -> Any:
        _validate_identifier(action, "action")
        _validate_identifier(resource, "resource")
        _validate_identifier(idempotency_key, "idempotency_key")
        if not isinstance(arguments, Mapping):
            raise ValueError("arguments must be a mapping")
        # The credential is verified by the configured identity provider; claims
        # supplied in arguments or request context are never treated as identity.
        try:
            principal = self.identity_provider.authenticate(credential)
            identity_context = principal.to_context()
            trusted_context = dict(self.context_provider.get_context(principal, action, resource))
        except Exception as exc:
            raise ContextUnavailable("trusted authentication/context retrieval failed") from exc
        if "identity" in trusted_context:
            raise ContextUnavailable("trusted context service must not override verified identity")
        # Verified identity is authoritative; context services may add attributes
        # but cannot replace the authentication result.
        context = {**trusted_context, **identity_context}
        request = {"principal": identity_context["identity"], "action": action,
                   "resource": resource, "arguments": dict(arguments), "context": context}
        decision = self.opa.decide(request)
        # Exclude volatile JWT timestamps and authentication-observation time from
        # the idempotency fingerprint, while retaining identity and authorization
        # claims that can change the policy outcome.
        stable_identity = dict(identity_context["identity"])
        stable_identity.pop("authenticated_at", None)
        stable_claims = dict(stable_identity.get("claims", {}))
        for temporal_claim in ("exp", "iat", "nbf", "jti"):
            stable_claims.pop(temporal_claim, None)
        stable_identity["claims"] = stable_claims
        stable_request = dict(request)
        stable_request["principal"] = stable_identity
        stable_context = dict(context)
        stable_context["identity"] = stable_identity
        stable_request["context"] = stable_context
        request_hash = _digest(stable_request)
        if not decision["allowed"]:
            with self.store._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    self.store._audit(db, "authorization_denied", None, action, resource,
                                      {"actor": {"subject": principal.subject, "issuer": principal.issuer,
                                                 "audience": principal.audience},
                                       "reason": decision["reason"], "request_hash": request_hash,
                                       "decision_id": decision.get("decision_id")})
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
            raise PermitRejected("OPA denied the operation")
        actor = {"subject": principal.subject, "issuer": principal.issuer,
                 "audience": principal.audience}
        permit_id = self.store.issue(action, resource, request_hash,
                                     decision["policy_version"], idempotency_key=idempotency_key,
                                     actor=actor)
        # Adapter must make this downstream key durable/idempotent or provide a
        # reconciliation API. Local authorization cannot make arbitrary APIs atomic.
        # Check the live marker again immediately before the guarded effect. This
        # narrows (but cannot eliminate) the distributed race with OPA bundle reload;
        # high-assurance deployments must coordinate policy rollout with effect commit.
        current_policy_version = self.opa.get_policy_version()
        return self.store.execute(
            permit_id, action, resource, request_hash, current_policy_version,
            lambda: adapter.invoke(action, resource, arguments, idempotency_key),
            idempotency_key=idempotency_key,
        )
