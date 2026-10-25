-- PACA++ PostgreSQL bootstrap for a fresh deployment.
-- Run as a trusted database administrator against the target database, for example:
--   psql "$PACA_POSTGRES_ADMIN_DSN" -v ON_ERROR_STOP=1 -f deployment/001_runtime_roles_and_schema.sql
-- This script creates roles with no password assigned. Configure login authentication
-- out-of-band using your secret manager / cloud IAM / client certificates.
--
-- IMPORTANT: review and adapt database/schema names, backup policy, and role grants
-- to your environment. Do not run this automatically from the application service.

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paca_migrator') THEN
        CREATE ROLE paca_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paca_runtime') THEN
        CREATE ROLE paca_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paca_operator') THEN
        CREATE ROLE paca_operator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
END
$roles$;

ALTER ROLE paca_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
ALTER ROLE paca_runtime NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
ALTER ROLE paca_operator NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
ALTER ROLE paca_runtime SET search_path TO paca, public;
ALTER ROLE paca_operator SET search_path TO paca, public;

CREATE SCHEMA IF NOT EXISTS paca AUTHORIZATION paca_migrator;
ALTER SCHEMA paca OWNER TO paca_migrator;
REVOKE ALL ON SCHEMA paca FROM PUBLIC;
GRANT USAGE ON SCHEMA paca TO paca_runtime, paca_operator;

SET ROLE paca_migrator;
SET search_path TO paca, public;

CREATE TABLE IF NOT EXISTS operations (
    operation_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL,
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
    error_code TEXT,
    UNIQUE(principal_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS operations_status_started ON operations(status, started_at);

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
);

CREATE TABLE IF NOT EXISTS audit_head (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    head_hash TEXT NOT NULL
);

INSERT INTO audit_head(singleton,head_hash)
VALUES(1,'0000000000000000000000000000000000000000000000000000000000000000')
ON CONFLICT (singleton) DO NOTHING;

RESET ROLE;

-- Use column-level UPDATE grants rather than table-level UPDATE. This prevents
-- runtime/operator SQL access from rewriting immutable request identity, idempotency
-- fingerprints, creation/expiry timestamps, action/resource, or argument/context digests.
REVOKE ALL ON TABLE paca.operations FROM PUBLIC;
REVOKE ALL ON TABLE paca.audit_events FROM PUBLIC;
REVOKE ALL ON TABLE paca.audit_head FROM PUBLIC;
REVOKE ALL ON SEQUENCE paca.audit_events_seq_seq FROM PUBLIC;
-- Also remove table-level UPDATE grants left by an earlier revision of this
-- bootstrap script; column grants below do not override broader old grants.
REVOKE UPDATE ON TABLE paca.operations FROM paca_runtime, paca_operator;
REVOKE UPDATE ON TABLE paca.audit_head FROM paca_runtime, paca_operator;

GRANT SELECT, INSERT ON TABLE paca.operations TO paca_runtime;
GRANT UPDATE (status, started_at, finished_at, response_json, error_code, policy_decision_json)
    ON TABLE paca.operations TO paca_runtime;
GRANT SELECT, INSERT ON TABLE paca.audit_events TO paca_runtime;
GRANT SELECT, UPDATE (head_hash) ON TABLE paca.audit_head TO paca_runtime;
GRANT USAGE, SELECT ON SEQUENCE paca.audit_events_seq_seq TO paca_runtime;

GRANT SELECT ON TABLE paca.operations TO paca_operator;
GRANT UPDATE (status, finished_at, response_json, error_code)
    ON TABLE paca.operations TO paca_operator;
GRANT SELECT, INSERT ON TABLE paca.audit_events TO paca_operator;
GRANT SELECT, UPDATE (head_hash) ON TABLE paca.audit_head TO paca_operator;
GRANT USAGE, SELECT ON SEQUENCE paca.audit_events_seq_seq TO paca_operator;

-- Ensure new tables created by a future migration are not accidentally PUBLIC-writable.
ALTER DEFAULT PRIVILEGES FOR ROLE paca_migrator IN SCHEMA paca REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE paca_migrator IN SCHEMA paca REVOKE ALL ON SEQUENCES FROM PUBLIC;

-- Grant connection to whichever database this migration was run against,
-- so CI and deployments with a non-default database name use the same migration.
DO $grant_connect$
BEGIN
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO paca_runtime, paca_operator',
        current_database()
    );
END
$grant_connect$;
