from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime

import psycopg
import pytest
from psycopg.rows import dict_row

from paca_service.audit_exporter import (
    AuditExportError,
    AuditWORMExporter,
    S3ObjectLockSink,
    canonical_bytes,
    canonical_event,
)


class FakeS3NotFound(Exception):
    response = {"Error": {"Code": "NoSuchKey"}, "ResponseMetadata": {"HTTPStatusCode": 404}}


class FakeS3PreconditionFailed(Exception):
    response = {
        "Error": {"Code": "PreconditionFailed"},
        "ResponseMetadata": {"HTTPStatusCode": 412},
    }


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.put_calls = []
        self.object_lock_enabled = True
        self.versioning_enabled = True

    def get_object_lock_configuration(self, **_kwargs):
        return {
            "ObjectLockConfiguration": {
                "ObjectLockEnabled": "Enabled" if self.object_lock_enabled else "Disabled"
            }
        }

    def get_bucket_versioning(self, **_kwargs):
        return {"Status": "Enabled" if self.versioning_enabled else "Suspended"}

    def head_object(self, *, Bucket, Key):
        item = self.objects.get((Bucket, Key))
        if item is None:
            raise FakeS3NotFound()
        return {
            "Metadata": item["Metadata"],
            "ObjectLockMode": item["ObjectLockMode"],
            "ObjectLockRetainUntilDate": item["ObjectLockRetainUntilDate"],
            "ContentLength": len(item["Body"]),
        }

    def put_object(self, **kwargs):
        object_key = (kwargs["Bucket"], kwargs["Key"])
        if kwargs.get("IfNoneMatch") == "*" and object_key in self.objects:
            raise FakeS3PreconditionFailed()
        self.put_calls.append(kwargs)
        self.objects[object_key] = {
            **kwargs,
            "Metadata": kwargs["Metadata"],
            "ObjectLockMode": kwargs["ObjectLockMode"],
            "ObjectLockRetainUntilDate": kwargs["ObjectLockRetainUntilDate"],
        }


def sample_row():
    return {
        "event_id": 42,
        "occurred_at": datetime(2026, 11, 14, 12, 30, tzinfo=UTC),
        "request_id": "req-42",
        "tenant_id": "tenant-a",
        "principal_id": "user-a",
        "event_type": "execution_succeeded",
        "action": "file.read",
        "resource_id": "report-42",
        "permit_id": "00000000-0000-0000-0000-000000000042",
        "execution_id": "00000000-0000-0000-0000-000000000043",
        "reason_code": None,
        "policy_revision": "policy-1",
        "decision_id": "decision-42",
        "arguments_digest": "a" * 64,
        "context_digest": "b" * 64,
        "details": {"bytes_read": 12},
    }


def sink(client=None):
    return S3ObjectLockSink(
        client or FakeS3(),
        bucket="independent-audit-bucket",
        prefix="paca/prod",
        retention_days=3650,
        kms_key_id="arn:aws:kms:us-east-1:111122223333:key/example",
        clock=lambda: datetime(2026, 11, 15, tzinfo=UTC),
    )


def test_canonical_audit_event_is_deterministic_and_includes_integrity_fields():
    event = canonical_event(sample_row())
    first = canonical_bytes(event)
    second = canonical_bytes(canonical_event(sample_row()))
    assert first == second
    assert b'"event_id":42' in first
    assert b'"tenant_id":"tenant-a"' in first
    assert b'"arguments_digest":"' + b"a" * 64 + b'"' in first


def test_s3_sink_uses_conditional_compliance_lock_kms_and_sha256_checksum():
    client = FakeS3()
    object_sink = sink(client)
    object_sink.verify_bucket_configuration()
    event = canonical_event(sample_row())
    body = canonical_bytes(event)
    digest = hashlib.sha256(body).hexdigest()
    key = object_sink.put_event(event, body, digest)

    assert key == "paca/prod/events/00000000000000000042.json"
    uploaded = client.put_calls[0]
    assert uploaded["ObjectLockMode"] == "COMPLIANCE"
    assert uploaded["ObjectLockRetainUntilDate"] == datetime(2036, 11, 13, tzinfo=UTC)
    assert uploaded["ServerSideEncryption"] == "aws:kms"
    assert uploaded["SSEKMSKeyId"].endswith("key/example")
    assert uploaded["Metadata"]["sha256"] == digest
    assert uploaded["ChecksumSHA256"] == base64.b64encode(bytes.fromhex(digest)).decode("ascii")
    assert uploaded["IfNoneMatch"] == "*"


def test_s3_sink_retries_are_idempotent_and_do_not_create_a_new_version():
    client = FakeS3()
    object_sink = sink(client)
    event = canonical_event(sample_row())
    body = canonical_bytes(event)
    digest = hashlib.sha256(body).hexdigest()
    first = object_sink.put_event(event, body, digest)
    second = object_sink.put_event(event, body, digest)
    assert first == second
    assert len(client.put_calls) == 1

    changed = dict(event)
    changed["details"] = {"bytes_read": 999}
    changed_body = canonical_bytes(changed)
    with pytest.raises(AuditExportError, match="digest_mismatch"):
        object_sink.put_event(changed, changed_body, hashlib.sha256(changed_body).hexdigest())


def test_s3_sink_accepts_conditional_write_race_only_when_existing_digest_matches():
    client = FakeS3()
    object_sink = sink(client)
    event = canonical_event(sample_row())
    body = canonical_bytes(event)
    digest = hashlib.sha256(body).hexdigest()
    key = object_sink._key(event["event_id"])
    retained_until = datetime(2036, 11, 13, tzinfo=UTC)
    # Simulate a concurrent writer winning after this exporter performed HEAD.
    client.objects[("independent-audit-bucket", key)] = {
        "Body": body,
        "Metadata": {"sha256": digest},
        "ObjectLockMode": "COMPLIANCE",
        "ObjectLockRetainUntilDate": retained_until,
    }
    # Force this attempt to see a miss on its first HEAD, then a 412 on PUT.
    original_head = client.head_object
    head_calls = [0]

    def racing_head(**kwargs):
        head_calls[0] += 1
        if head_calls[0] == 1:
            raise FakeS3NotFound()
        return original_head(**kwargs)

    client.head_object = racing_head
    assert object_sink.put_event(event, body, digest) == key
    assert client.put_calls == []


@pytest.mark.parametrize(
    "lock_enabled,versioning_enabled",
    [(False, True), (True, False)],
)
def test_s3_sink_rejects_bucket_without_object_lock_or_versioning(
    lock_enabled, versioning_enabled
):
    client = FakeS3()
    client.object_lock_enabled = lock_enabled
    client.versioning_enabled = versioning_enabled
    with pytest.raises(AuditExportError):
        sink(client).verify_bucket_configuration()


def test_s3_sink_rejects_existing_governance_or_expired_retention_object():
    client = FakeS3()
    object_sink = sink(client)
    event = canonical_event(sample_row())
    body = canonical_bytes(event)
    digest = hashlib.sha256(body).hexdigest()
    key = object_sink.put_event(event, body, digest)
    saved = client.objects[("independent-audit-bucket", key)]
    saved["ObjectLockMode"] = "GOVERNANCE"
    with pytest.raises(AuditExportError, match="not_compliance_locked"):
        object_sink.put_event(event, body, digest)

    saved["ObjectLockMode"] = "COMPLIANCE"
    saved["ObjectLockRetainUntilDate"] = datetime(2026, 11, 14, tzinfo=UTC)
    with pytest.raises(AuditExportError, match="retention_expired"):
        object_sink.put_event(event, body, digest)


def test_canonical_event_rejects_naive_timestamps_and_non_json_details():
    row = sample_row()
    row["occurred_at"] = datetime(2026, 11, 14)
    with pytest.raises(AuditExportError, match="timezone_aware"):
        canonical_event(row)

    row = sample_row()
    row["details"] = {"not_json": object()}
    with pytest.raises(AuditExportError, match="finite_json"):
        canonical_event(row)


@pytest.mark.skipif(
    not (
        os.environ.get("PACA_TEST_ADMIN_DATABASE_URL")
        and os.environ.get("PACA_TEST_AUDIT_EXPORT_DATABASE_URL")
    ),
    reason="PostgreSQL audit-export admin and restricted exporter DSNs are required",
)
def test_postgres_exporter_delivers_audit_row_and_cannot_mutate_source():
    admin_dsn = os.environ["PACA_TEST_ADMIN_DATABASE_URL"]
    exporter_dsn = os.environ["PACA_TEST_AUDIT_EXPORT_DATABASE_URL"]
    with psycopg.connect(admin_dsn, row_factory=dict_row) as admin:
        row = admin.execute(
            """
            INSERT INTO public.audit_events
                (request_id, tenant_id, principal_id, event_type, action, resource_id, details)
            VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
            RETURNING event_id
            """,
            (
                "audit-export-ci-" + os.urandom(8).hex(),
                "tenant-audit-export",
                "principal-audit-export",
                "audit_export_ci_test",
                "file.read",
                "audit-test-resource",
                json.dumps({"ci": True}),
            ),
        ).fetchone()
        event_id = row["event_id"]

    client = FakeS3()
    exporter = AuditWORMExporter(exporter_dsn, sink(client), batch_size=500)
    total_exported = 0
    while True:
        exported_now = exporter.export_once()
        total_exported += exported_now
        if exported_now == 0:
            break
    assert total_exported >= 1
    assert exporter.export_once() == 0

    key = f"paca/prod/events/{event_id:020d}.json"
    saved = client.objects[("independent-audit-bucket", key)]
    assert json.loads(saved["Body"])["event_id"] == event_id
    assert saved["ObjectLockMode"] == "COMPLIANCE"

    with psycopg.connect(admin_dsn) as admin:
        exists = admin.execute(
            "SELECT 1 FROM public.audit_events WHERE event_id = %s", (event_id,)
        ).fetchone()
        assert exists is not None

    with psycopg.connect(exporter_dsn) as exporter_conn:
        exporter_conn.execute("SET ROLE paca_audit_exporter")
        exporter_conn.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            exporter_conn.execute(
                "DELETE FROM public.audit_events WHERE event_id = %s", (event_id,)
            )
        exporter_conn.rollback()
