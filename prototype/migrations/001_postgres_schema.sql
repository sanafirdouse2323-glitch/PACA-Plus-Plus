-- PACA++ PostgreSQL durable state schema, migration 001.
-- Run as a dedicated migration role. The service runtime role should receive only
-- the DML privileges it needs after this schema has been provisioned.
BEGIN;

CREATE TABLE IF NOT EXISTS paca_permits (
    permit_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    actor_json JSONB,
    policy_version TEXT NOT NULL,
    state_version BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL CHECK (status IN
        ('issued', 'executing', 'completed', 'failed', 'unknown', 'rejected')),
    idempotency_key TEXT,
    result_json JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
ALTER TABLE paca_permits ADD COLUMN IF NOT EXISTS actor_json JSONB;

CREATE INDEX IF NOT EXISTS paca_permits_status_idx ON paca_permits(status);
CREATE INDEX IF NOT EXISTS paca_permits_idempotency_idx ON paca_permits(idempotency_key);

CREATE TABLE IF NOT EXISTS paca_idempotency (
    idempotency_key TEXT PRIMARY KEY,
    request_hash TEXT NOT NULL,
    permit_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN
        ('issued', 'executing', 'completed', 'failed', 'unknown', 'rejected')),
    result_json JSONB,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS paca_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    state_version BIGINT NOT NULL
);

INSERT INTO paca_state(singleton, state_version)
VALUES (1, 0)
ON CONFLICT (singleton) DO NOTHING;

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
);

CREATE TABLE IF NOT EXISTS paca_audit_head (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    event_hash TEXT NOT NULL
);

INSERT INTO paca_audit_head(singleton, event_hash)
SELECT 1, COALESCE(
    (SELECT event_hash FROM paca_audit ORDER BY sequence DESC LIMIT 1),
    repeat('0', 64)
)
ON CONFLICT (singleton) DO NOTHING;

COMMIT;
