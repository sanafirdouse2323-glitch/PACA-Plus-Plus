-- PACA++ transactional audit delivery outbox, migration 003.
-- Existing hash-chain events are queued by apply_postgres_migration.py after
-- applying migrations. Delivery is at-least-once; the independent sink must
-- deduplicate by event_id and verify event_hash.
BEGIN;

CREATE TABLE IF NOT EXISTS paca_audit_outbox (
    sequence BIGSERIAL PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    payload_json TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL,
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    last_error_type TEXT
);

CREATE INDEX IF NOT EXISTS paca_audit_outbox_pending_idx
    ON paca_audit_outbox (delivered_at, next_attempt_at, lease_expires_at, sequence);

COMMIT;
