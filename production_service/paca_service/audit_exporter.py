from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from psycopg.rows import dict_row

_LOG = logging.getLogger("paca.audit_export")
_ADVISORY_LOCK_ID = 0x5041434141554449  # "PACAAUDI"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_EVENT_QUERY = """
SELECT
    e.event_id,
    e.occurred_at,
    e.request_id,
    e.tenant_id,
    e.principal_id,
    e.event_type,
    e.action,
    e.resource_id,
    e.permit_id,
    e.execution_id,
    e.reason_code,
    e.policy_revision,
    e.decision_id,
    e.arguments_digest,
    e.context_digest,
    e.details
FROM public.audit_events AS e
LEFT JOIN paca_audit.exported_events AS x
    ON x.event_id = e.event_id
WHERE x.event_id IS NULL
ORDER BY e.event_id ASC
LIMIT %s
"""


class AuditExportError(RuntimeError):
    """A source event could not be safely placed in independent immutable storage."""


def _not_found(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error", {})
        metadata = response.get("ResponseMetadata", {})
        code = error.get("Code")
        status = metadata.get("HTTPStatusCode")
        return code in {"404", "NoSuchKey", "NotFound"} or status == 404
    return isinstance(exc, KeyError)


def _as_iso(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise AuditExportError("audit_event_timestamp_has_invalid_type")
    if value.tzinfo is None:
        raise AuditExportError("audit_event_timestamp_must_be_timezone_aware")
    return value.astimezone(UTC).isoformat()


def canonical_event(row: dict[str, Any]) -> dict[str, Any]:
    """Convert a PostgreSQL audit row to a stable, finite JSON event envelope."""
    required = ("event_id", "occurred_at", "event_type", "details")
    if any(name not in row for name in required):
        raise AuditExportError("audit_event_row_missing_required_field")
    if not isinstance(row["event_type"], str) or not row["event_type"]:
        raise AuditExportError("audit_event_type_invalid")
    details = row.get("details") or {}
    if not isinstance(details, dict):
        raise AuditExportError("audit_event_details_invalid")

    event: dict[str, Any] = {
        "schema_version": 1,
        "event_id": int(row["event_id"]),
        "occurred_at": _as_iso(row["occurred_at"]),
        "request_id": row.get("request_id"),
        "tenant_id": row.get("tenant_id"),
        "principal_id": row.get("principal_id"),
        "event_type": row["event_type"],
        "action": row.get("action"),
        "resource_id": row.get("resource_id"),
        "permit_id": str(row["permit_id"]) if row.get("permit_id") is not None else None,
        "execution_id": (
            str(row["execution_id"]) if row.get("execution_id") is not None else None
        ),
        "reason_code": row.get("reason_code"),
        "policy_revision": row.get("policy_revision"),
        "decision_id": row.get("decision_id"),
        "arguments_digest": (
            str(row["arguments_digest"]).strip()
            if row.get("arguments_digest") is not None
            else None
        ),
        "context_digest": (
            str(row["context_digest"]).strip()
            if row.get("context_digest") is not None
            else None
        ),
        "details": details,
    }
    try:
        json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise AuditExportError("audit_event_is_not_finite_json") from exc
    return event


def canonical_bytes(event: dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            event, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise AuditExportError("audit_event_serialization_failed") from exc


class S3ObjectLockSink:
    """Write immutable audit objects to an independently administered S3 bucket.

    The bucket must be created with Object Lock enabled, versioning enabled, and
    owned by a separate AWS account/control plane. The caller's IAM role must not
    have DeleteObject, DeleteObjectVersion, retention-bypass, or bucket-policy
    administration permissions.
    """

    def __init__(
        self,
        client: Any,
        *,
        bucket: str,
        prefix: str,
        retention_days: int,
        kms_key_id: str,
        clock=lambda: datetime.now(UTC),
    ) -> None:
        if not isinstance(bucket, str) or not bucket or "/" in bucket:
            raise ValueError("audit_s3_bucket_invalid")
        if not isinstance(prefix, str) or prefix.startswith("/") or ".." in prefix.split("/"):
            raise ValueError("audit_s3_prefix_invalid")
        if (
            isinstance(retention_days, bool)
            or not isinstance(retention_days, int)
            or not 1 <= retention_days <= 36500
        ):
            raise ValueError("audit_object_lock_retention_days_invalid")
        if not isinstance(kms_key_id, str) or not kms_key_id.strip():
            raise ValueError("audit_s3_kms_key_id_required")
        self.client = client
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.retention_days = retention_days
        self.kms_key_id = kms_key_id
        self.clock = clock

    def verify_bucket_configuration(self) -> None:
        try:
            lock = self.client.get_object_lock_configuration(Bucket=self.bucket)
            versioning = self.client.get_bucket_versioning(Bucket=self.bucket)
        except Exception as exc:
            raise AuditExportError("audit_s3_bucket_configuration_unavailable") from exc
        lock_enabled = lock.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled")
        if lock_enabled != "Enabled":
            raise AuditExportError("audit_s3_object_lock_not_enabled")
        if versioning.get("Status") != "Enabled":
            raise AuditExportError("audit_s3_bucket_versioning_not_enabled")

    def _key(self, event_id: int) -> str:
        return f"{self.prefix}/events/{event_id:020d}.json"

    def _head(self, key: str) -> dict[str, Any] | None:
        try:
            return self.client.head_object(Bucket=self.bucket, Key=key)
        except Exception as exc:
            if _not_found(exc):
                return None
            raise AuditExportError("audit_s3_head_object_failed") from exc

    def _verify_existing(self, head: dict[str, Any], digest: str) -> None:
        metadata = head.get("Metadata") or {}
        if metadata.get("sha256") != digest:
            raise AuditExportError("audit_s3_existing_object_digest_mismatch")
        if head.get("ObjectLockMode") != "COMPLIANCE":
            raise AuditExportError("audit_s3_existing_object_not_compliance_locked")
        retained_until = head.get("ObjectLockRetainUntilDate")
        if not isinstance(retained_until, datetime) or retained_until.tzinfo is None:
            raise AuditExportError("audit_s3_existing_object_retention_missing")
        if retained_until <= self.clock():
            raise AuditExportError("audit_s3_existing_object_retention_expired")

    def put_event(self, event: dict[str, Any], body: bytes, digest: str) -> str:
        event_id = event.get("event_id")
        if (
            not isinstance(event_id, int)
            or isinstance(event_id, bool)
            or event_id < 1
            or not isinstance(digest, str)
            or not _SHA256_RE.fullmatch(digest)
        ):
            raise AuditExportError("audit_s3_event_identity_or_digest_invalid")
        actual_digest = hashlib.sha256(body).hexdigest()
        if actual_digest != digest:
            raise AuditExportError("audit_s3_payload_digest_mismatch")

        key = self._key(event_id)
        existing = self._head(key)
        if existing is not None:
            self._verify_existing(existing, digest)
            return key

        retained_until = self.clock() + timedelta(days=self.retention_days)
        checksum = base64.b64encode(bytes.fromhex(digest)).decode("ascii")
        try:
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=body,
                ContentType="application/json",
                Metadata={"event-id": str(event_id), "sha256": digest},
                ChecksumSHA256=checksum,
                ServerSideEncryption="aws:kms",
                SSEKMSKeyId=self.kms_key_id,
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=retained_until,
                IfNoneMatch="*",
            )
        except Exception as exc:
            response = getattr(exc, "response", {})
            error = response.get("Error", {}) if isinstance(response, dict) else {}
            metadata = (
                response.get("ResponseMetadata", {}) if isinstance(response, dict) else {}
            )
            status = metadata.get("HTTPStatusCode")
            code = error.get("Code")
            if status in {409, 412} or code in {
                "PreconditionFailed",
                "ConditionalRequestConflict",
            }:
                # Another writer won the conditional create. Accept only the
                # exact expected digest and still-valid COMPLIANCE retention.
                raced = self._head(key)
                if raced is not None:
                    self._verify_existing(raced, digest)
                    return key
                raise AuditExportError("audit_s3_conditional_write_conflict") from exc
            # A crash after PUT but before checkpoint insert is recovered by
            # the next invocation's HEAD + digest/retention verification path.
            raise AuditExportError("audit_s3_object_write_failed") from exc

        written = self._head(key)
        if written is None:
            raise AuditExportError("audit_s3_object_missing_after_write")
        self._verify_existing(written, digest)
        return key


class AuditWORMExporter:
    """At-least-once PostgreSQL-to-S3 Object-Lock audit exporter.

    It never advances a numeric high-water mark. Each run selects every source
    audit row that lacks a local export-state row. This avoids losing a lower
    BIGSERIAL ID when concurrent PostgreSQL transactions commit out of ID order.
    S3 object IDs are deterministic; retries verify the pre-existing immutable
    object's checksum and retention before recording local delivery state.
    """

    def __init__(
        self,
        database_url: str,
        sink: S3ObjectLockSink,
        *,
        batch_size: int = 100,
        connection_factory=psycopg.connect,
    ) -> None:
        if not isinstance(database_url, str) or not database_url:
            raise ValueError("audit_export_database_url_required")
        if (
            isinstance(batch_size, bool)
            or not isinstance(batch_size, int)
            or not 1 <= batch_size <= 10000
        ):
            raise ValueError("audit_export_batch_size_invalid")
        self.database_url = database_url
        self.sink = sink
        self.batch_size = batch_size
        self.connection_factory = connection_factory

    def export_once(self) -> int:
        exported = 0
        try:
            with self.connection_factory(self.database_url, row_factory=dict_row) as conn:
                conn.execute("SET ROLE paca_audit_exporter")
                conn.commit()
                acquired = conn.execute(
                    "SELECT pg_try_advisory_lock(%s) AS acquired",
                    (_ADVISORY_LOCK_ID,),
                ).fetchone()["acquired"]
                conn.commit()
                if not acquired:
                    return 0
                try:
                    rows = conn.execute(_EVENT_QUERY, (self.batch_size,)).fetchall()
                    conn.commit()
                    for row in rows:
                        event = canonical_event(dict(row))
                        body = canonical_bytes(event)
                        digest = hashlib.sha256(body).hexdigest()
                        object_key = self.sink.put_event(event, body, digest)
                        with conn.transaction():
                            conn.execute(
                                """
                                INSERT INTO paca_audit.exported_events
                                    (event_id, event_sha256, object_key)
                                VALUES (%s, %s, %s)
                                ON CONFLICT (event_id) DO NOTHING
                                """,
                                (event["event_id"], digest, object_key),
                            )
                            stored = conn.execute(
                                """
                                SELECT event_sha256, object_key
                                FROM paca_audit.exported_events
                                WHERE event_id = %s
                                """,
                                (event["event_id"],),
                            ).fetchone()
                            if (
                                stored is None
                                or stored["event_sha256"].strip() != digest
                                or stored["object_key"] != object_key
                            ):
                                raise AuditExportError("audit_export_state_conflict")
                        exported += 1
                finally:
                    conn.execute(
                        "SELECT pg_advisory_unlock(%s)",
                        (_ADVISORY_LOCK_ID,),
                    )
                    conn.commit()
        except AuditExportError:
            raise
        except Exception as exc:
            raise AuditExportError("audit_export_database_operation_failed") from exc
        return exported


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError(
            "Install the audit-export extra: pip install '.[audit-export]'"
        ) from exc

    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if not region:
        raise RuntimeError("AWS_REGION or AWS_DEFAULT_REGION is required")
    client = boto3.client("s3", region_name=region)
    sink = S3ObjectLockSink(
        client,
        bucket=_required_env("PACA_AUDIT_S3_BUCKET"),
        prefix=os.environ.get("PACA_AUDIT_S3_PREFIX", "paca-audit"),
        retention_days=int(_required_env("PACA_AUDIT_RETENTION_DAYS")),
        kms_key_id=_required_env("PACA_AUDIT_S3_KMS_KEY_ID"),
    )
    sink.verify_bucket_configuration()
    exporter = AuditWORMExporter(
        _required_env("PACA_AUDIT_EXPORT_DATABASE_URL"),
        sink,
        batch_size=int(os.environ.get("PACA_AUDIT_EXPORT_BATCH_SIZE", "100")),
    )
    poll_seconds = float(os.environ.get("PACA_AUDIT_EXPORT_POLL_SECONDS", "5"))
    if not 0.2 <= poll_seconds <= 3600:
        raise RuntimeError("PACA_AUDIT_EXPORT_POLL_SECONDS must be between 0.2 and 3600")
    while True:
        count = exporter.export_once()
        if count:
            _LOG.info("exported %s audit event(s) to immutable storage", count)
        else:
            time.sleep(poll_seconds)


if __name__ == "__main__":
    main()
