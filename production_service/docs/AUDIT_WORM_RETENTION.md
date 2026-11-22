# Independent WORM audit retention

## Security boundary

The production service's `public.audit_events` table is tenant-scoped and append-only for the `paca_runtime` database role. That protects application-level writes, but the table still resides inside the production PostgreSQL administrative boundary. A PostgreSQL superuser or administrator with table-owner privileges can alter the database.

This optional exporter creates a second copy in an independently administered S3 account/bucket. It is a retention integration, not an external audit or a guarantee that the source database was honest before export.

## 1. PostgreSQL exporter role

Apply `production_service/paca_service/audit_export.sql` as the trusted schema administrator after `schema.sql` and `runtime_grants.sql`.

The migration creates:

- `paca_audit_exporter`: a `NOLOGIN`, `BYPASSRLS`, non-superuser role. It is intentionally able to read every tenant's audit rows so one exporter can create a complete external archive.
- `paca_audit.exported_events`: a local delivery checkpoint keyed by `event_id`, holding the canonical event digest and immutable object key.

The role has `SELECT` on `public.audit_events` and `SELECT, INSERT` on `paca_audit.exported_events`. It receives no access to protected resources, permits, executions, or `paca_private`. The normal `paca_runtime` role receives no privileges on `paca_audit`.

Create a separate login for the exporter and grant membership in `paca_audit_exporter`. Only this service identity should be able to `SET ROLE paca_audit_exporter`. Do not grant the exporter role to the API runtime or to human application accounts. The CI workflow creates a test-only login to verify this grant boundary.

## 2. S3 Object Lock bucket and KMS key

Use an S3 general-purpose bucket owned by a different AWS account or by a separate cloud security team/control plane. Enable S3 Versioning and Object Lock. Choose the retention policy before production use: COMPLIANCE retention cannot be shortened or bypassed for an object version before its retain-until date. Enabling Object Lock is an irreversible bucket configuration decision; validate the retention period, legal requirements, costs, lifecycle and recovery process first.

The exporter verifies that Object Lock and bucket versioning are enabled. For each event it writes a canonical JSON object under a deterministic key, requires a SHA-256 checksum, uses SSE-KMS with the configured customer-managed key, and sets per-object COMPLIANCE retention. The write includes `If-None-Match: *`, so S3 rejects a second write to an already-existing key instead of creating a newer version under that key. If another writer wins a race, the exporter accepts it only after checking the exact expected digest and still-valid COMPLIANCE retention.

The exporter identity needs only the necessary permissions for:
- `s3:GetBucketObjectLockConfiguration` and `s3:GetBucketVersioning` on the bucket;
- `s3:GetObject` and `s3:GetObjectRetention` for the configured prefix (including the `HeadObject` checks);
- `s3:PutObject` and `s3:PutObjectRetention` for new retained objects;
- the KMS permissions required by SSE-KMS uploads, scoped to the dedicated key.

Explicitly deny `s3:DeleteObject`, `s3:DeleteObjectVersion`, retention bypass, bucket-policy changes, Object Lock configuration changes and KMS key administration to the exporter identity. Do not grant `s3:BypassGovernanceRetention`. The bucket account should enforce the policy independently of the exporting workload.

AWS notes that Object Lock works only with versioned buckets and protects object versions; a new version can otherwise be written at the same key. The conditional `If-None-Match: *` request protects this exporter's deterministic key convention against a second successful PUT. See the [S3 Object Lock configuration guide](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-configure.html), [Object Lock overview](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html), and [Boto3 PutObject reference](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/put_object.html).

## 3. Run the exporter

Install the optional extra:

```sh
python -m pip install -e "production_service[audit-export]"
```

Use a short-lived role/credential provider such as an EC2 instance profile, ECS task role or Kubernetes workload identity. Do not put static AWS keys in the environment or repository. Configure:

```dotenv
PACA_AUDIT_EXPORT_DATABASE_URL=postgresql://paca_audit_exporter_login:<secret>@database:5432/paca
PACA_AUDIT_S3_BUCKET=<separate-account-object-lock-bucket>
PACA_AUDIT_S3_PREFIX=paca/production
PACA_AUDIT_S3_KMS_KEY_ID=<customer-managed-kms-key-arn>
PACA_AUDIT_RETENTION_DAYS=<approved-retention-days>
PACA_AUDIT_EXPORT_BATCH_SIZE=100
PACA_AUDIT_EXPORT_POLL_SECONDS=5
AWS_REGION=<bucket-region>
```

Start it under a dedicated process supervisor:

```sh
paca-audit-export
```

Monitor process health, export lag, last exported event ID/time, export failures, S3 retention, KMS availability, bucket-policy drift and any period where audit generation continues but export stops. Restrict access to exporter logs because they can reveal tenant identifiers and event metadata.

## 4. Delivery and recovery properties

The exporter is at-least-once. It scans for audit events without a matching delivery-checkpoint row; it does not use a numeric high-water cursor, avoiding a gap if concurrent database transactions commit out of BIGSERIAL allocation order. A PostgreSQL advisory lock prevents multiple exporter instances using this database from scanning concurrently.

If the exporter crashes after the S3 PUT but before it records the local checkpoint, the next run sees the deterministic object key and verifies the recorded SHA-256 metadata, COMPLIANCE lock mode and remaining retention before recording delivery. If an object with that key contains different data, has no lock, or has expired retention, export fails closed and does not mark the event delivered.

The source audit table is not deleted, updated or pruned by this exporter. Export checkpoints are stored separately. Restoring the source database or checkpoint table does not remove the external copy, but it can cause verified duplicate delivery attempts; the deterministic object key and conditional PUT handle that case.

## 5. Verification and limits

CI runs the exporter against PostgreSQL with a separate restricted login and a fake S3 API. It verifies the role's read-only source boundary, export-state insert, canonical body, idempotent retry, checksum, COMPLIANCE request and retention checks. This does **not** verify an actual AWS account, bucket policy, KMS policy, cross-account trust, deployed role credentials, or external administrator independence.

Before relying on the archive for regulatory or incident-response purposes, provision the real bucket/KMS resources, review the bucket and IAM policies independently, perform a live test with the production workload identity, test restore/evidence retrieval, and have an independent security/compliance reviewer confirm the control boundary.
