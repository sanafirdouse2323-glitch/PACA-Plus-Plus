"""Durable at-least-once export of PACA++ audit events.

The local store writes the hash-chained audit event and its outbox entry in one
transaction. This worker delivers claimed events to a fixed HTTPS sink with
lease-based concurrency control and exponential retry. The sink must durably
deduplicate by event_id and validate the supplied event_hash; this module alone
does not make the remote destination immutable or tamper-proof.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import time
import uuid
from typing import Any, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request

from .hardening import (
    HardeningError,
    SQLitePermitStore,
    _canonical_json,
    _digest,
    _urlopen_no_redirect,
    _validate_identifier,
)
from .postgres import PostgresPermitStore


class AuditDeliveryError(RuntimeError):
    """An audit event could not be durably acknowledged by the configured sink."""


class AuditSink(Protocol):
    def append(self, event: Mapping[str, Any]) -> None:
        """Idempotently and durably append the event or raise an error."""


class AuditOutboxStore(Protocol):
    def verify_audit_chain(self) -> bool:
        """Verify the retained local audit chain and its separately stored head."""
        ...
    def claim_audit_outbox(
        self, worker_id: str, limit: int = 100, lease_seconds: int = 30
    ) -> list[dict[str, Any]]: ...
    def mark_audit_delivered(self, event_id: str, worker_id: str) -> None: ...
    def retry_audit_event(
        self, event_id: str, worker_id: str, error_type: str,
        retry_after_seconds: int,
    ) -> None: ...
    def audit_outbox_counts(self) -> dict[str, int]: ...


class HTTPSAuditSink:
    """Send events to a deployment-controlled HTTPS append endpoint.

    Contract expected of the remote endpoint:
    - validate event_hash against the canonical event payload;
    - durably accept an event before returning HTTP 2xx;
    - deduplicate Idempotency-Key/event_id and reject conflicting reuse;
    - independently enforce retention/append-only or WORM storage controls.
    """
    _ID_RE = re.compile(r"^[0-9a-f]{32}$")
    _HASH_RE = re.compile(r"^[0-9a-f]{64}$")

    def __init__(
        self, endpoint: str, bearer_token: str, timeout_seconds: float = 5.0,
        max_event_bytes: int = 1_048_576, max_response_bytes: int = 65_536,
    ):
        parsed = urlparse(endpoint)
        if (parsed.scheme != "https" or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("audit sink endpoint must be a fixed HTTPS URL without credentials/query/fragment")
        if (not isinstance(bearer_token, str) or len(bearer_token) < 16
                or not bearer_token.isascii() or bearer_token.strip() != bearer_token
                or any(ch.isspace() for ch in bearer_token)):
            raise ValueError("audit sink token must be an ASCII secret of at least 16 characters")
        if timeout_seconds <= 0 or max_event_bytes < 1 or max_response_bytes < 1:
            raise ValueError("invalid audit sink timeout or size limit")
        self.endpoint = endpoint
        self.bearer_token = bearer_token
        self.timeout_seconds = timeout_seconds
        self.max_event_bytes = max_event_bytes
        self.max_response_bytes = max_response_bytes

    def append(self, event: Mapping[str, Any]) -> None:
        payload = dict(event)
        event_id = payload.get("event_id")
        event_hash = payload.get("event_hash")
        if not isinstance(event_id, str) or not self._ID_RE.fullmatch(event_id):
            raise AuditDeliveryError("audit event has an invalid event_id")
        if not isinstance(event_hash, str) or not self._HASH_RE.fullmatch(event_hash):
            raise AuditDeliveryError("audit event has an invalid event_hash")
        unsigned = dict(payload)
        unsigned.pop("event_hash", None)
        if _digest(unsigned) != event_hash:
            raise AuditDeliveryError("audit event hash does not match its payload")
        try:
            body = _canonical_json(payload).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise AuditDeliveryError("audit event is not canonical JSON") from exc
        if len(body) > self.max_event_bytes:
            raise AuditDeliveryError("audit event exceeds configured request limit")

        request = Request(
            self.endpoint,
            data=body,
            method="POST",
            headers={
                "Authorization": "Bearer " + self.bearer_token,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Idempotency-Key": event_id,
                "X-PACA-Audit-Hash": event_hash,
            },
        )
        try:
            with _urlopen_no_redirect(request, timeout=self.timeout_seconds) as response:
                if response.status < 200 or response.status >= 300:
                    raise AuditDeliveryError(f"audit sink returned HTTP {response.status}")
                response_body = response.read(self.max_response_bytes + 1)
                if len(response_body) > self.max_response_bytes:
                    raise AuditDeliveryError("audit sink response exceeded configured limit")
        except AuditDeliveryError:
            raise
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            # Never include endpoint, body or raw exception text: they may carry
            # deployment-specific details or credentials.
            raise AuditDeliveryError("audit sink request failed; delivery will be retried") from exc


class AuditOutboxWorker:
    def __init__(
        self, store: AuditOutboxStore, sink: AuditSink, worker_id: str | None = None,
        lease_seconds: int = 30, base_retry_seconds: int = 2,
        max_retry_seconds: int = 3600,
    ):
        self.store = store
        self.sink = sink
        self.worker_id = worker_id or ("audit-" + uuid.uuid4().hex)
        _validate_identifier(self.worker_id, "worker_id")
        if not 1 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be 1..3600")
        if not 1 <= base_retry_seconds <= 3600:
            raise ValueError("base_retry_seconds must be 1..3600")
        if not base_retry_seconds <= max_retry_seconds <= 86400:
            raise ValueError("max_retry_seconds must be between base retry and 86400")
        self.lease_seconds = lease_seconds
        self.base_retry_seconds = base_retry_seconds
        self.max_retry_seconds = max_retry_seconds

    def run_once(self, limit: int = 100) -> dict[str, int]:
        # Refuse to export any local event if the chain integrity check fails.
        # This is tamper-evidence, not protection against an attacker who can
        # rewrite the entire chain/head or control the database administrator.
        if not self.store.verify_audit_chain():
            raise HardeningError(
                "local audit chain failed verification; refusing to export events"
            )
        claimed = self.store.claim_audit_outbox(
            self.worker_id, limit=limit, lease_seconds=self.lease_seconds
        )
        result = {
            "claimed": len(claimed), "delivered": 0, "retry_scheduled": 0,
            "retry_state_errors": 0, "ack_state_errors": 0,
        }
        for row in claimed:
            event_id = row["event_id"]
            try:
                payload = json.loads(row["payload_json"])
                if not isinstance(payload, dict) or payload.get("event_id") != event_id:
                    raise AuditDeliveryError("outbox event identity does not match its payload")
                event_hash = payload.get("event_hash")
                source_hash = row.get("source_event_hash")
                if (not isinstance(event_hash, str) or not isinstance(source_hash, str)
                        or event_hash != source_hash):
                    raise AuditDeliveryError("outbox hash does not match the source audit event")
                unsigned = dict(payload)
                unsigned.pop("event_hash", None)
                if _digest(unsigned) != source_hash:
                    raise AuditDeliveryError("outbox payload hash verification failed")
                self.sink.append(payload)
            except Exception as exc:
                attempts = max(1, int(row.get("attempts", 1)))
                delay = min(
                    self.max_retry_seconds,
                    self.base_retry_seconds * (2 ** min(attempts - 1, 20)),
                )
                try:
                    # Persist only the exception class; raw network messages may
                    # contain a URL, response body, or other sensitive details.
                    self.store.retry_audit_event(
                        event_id, self.worker_id, type(exc).__name__[:128], int(delay)
                    )
                    result["retry_scheduled"] += 1
                except Exception:
                    # Lease expiry provides recovery if the retry-state write also
                    # fails because the primary database is unavailable.
                    result["retry_state_errors"] += 1
                continue

            try:
                # If this ack fails after remote acceptance, lease expiry causes
                # a duplicate delivery; the sink must deduplicate by event_id.
                self.store.mark_audit_delivered(event_id, self.worker_id)
                result["delivered"] += 1
            except Exception:
                result["ack_state_errors"] += 1
        return result


def _build_worker_from_environment() -> tuple[AuditOutboxWorker, int, int]:
    endpoint = os.environ.get("PACA_AUDIT_SINK_URL", "").strip()
    token = os.environ.get("PACA_AUDIT_SINK_TOKEN", "")
    if not endpoint or not token:
        raise RuntimeError("PACA_AUDIT_SINK_URL and PACA_AUDIT_SINK_TOKEN are required")
    database_url = os.environ.get("PACA_DATABASE_URL", "").strip()
    if database_url:
        store: Any = PostgresPermitStore(database_url, initialize_schema=False)
    else:
        database_path = os.environ.get("PACA_SQLITE_PATH", "").strip()
        if not database_path:
            raise RuntimeError("set PACA_DATABASE_URL or PACA_SQLITE_PATH")
        store = SQLitePermitStore(database_path)

    worker_id = os.environ.get("PACA_AUDIT_WORKER_ID", "").strip() or None
    batch_size = int(os.environ.get("PACA_AUDIT_BATCH_SIZE", "100"))
    poll_seconds = int(os.environ.get("PACA_AUDIT_POLL_SECONDS", "5"))
    if not 1 <= batch_size <= 1000 or not 1 <= poll_seconds <= 3600:
        raise RuntimeError("PACA_AUDIT_BATCH_SIZE must be 1..1000 and PACA_AUDIT_POLL_SECONDS 1..3600")
    worker = AuditOutboxWorker(store, HTTPSAuditSink(endpoint, token), worker_id=worker_id)
    return worker, batch_size, poll_seconds


def main() -> None:
    parser = argparse.ArgumentParser(description="Deliver PACA++ audit outbox events to a durable HTTPS sink")
    parser.add_argument("--once", action="store_true", help="process one outbox batch and exit")
    args = parser.parse_args()
    worker, batch_size, poll_seconds = _build_worker_from_environment()
    while True:
        stats = worker.run_once(limit=batch_size)
        print(json.dumps({
            "worker_id": worker.worker_id,
            **stats,
            "outbox": worker.store.audit_outbox_counts(),
        }, sort_keys=True), flush=True)
        if args.once:
            return
        if stats["claimed"] == 0:
            time.sleep(poll_seconds)


if __name__ == "__main__":
    main()
