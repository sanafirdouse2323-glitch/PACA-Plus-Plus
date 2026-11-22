-- Independent audit export role and local delivery checkpoint.
-- Apply as the trusted PostgreSQL schema/migration administrator.
BEGIN;

DO $paca_role$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paca_audit_exporter') THEN
        CREATE ROLE paca_audit_exporter
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS;
    END IF;
END
$paca_role$;

ALTER ROLE paca_audit_exporter
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS;

CREATE SCHEMA IF NOT EXISTS paca_audit;
ALTER SCHEMA paca_audit OWNER TO CURRENT_USER;
REVOKE ALL ON SCHEMA paca_audit FROM PUBLIC;

CREATE TABLE IF NOT EXISTS paca_audit.exported_events (
    event_id BIGINT PRIMARY KEY,
    event_sha256 CHAR(64) NOT NULL
        CHECK (event_sha256 ~ '^[0-9a-f]{64}$'),
    object_key TEXT NOT NULL UNIQUE,
    exported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE paca_audit.exported_events OWNER TO CURRENT_USER;
REVOKE ALL ON TABLE paca_audit.exported_events FROM PUBLIC;

-- The exporter role is intentionally not a member of paca_runtime and cannot
-- read permits, executions, protected resources, or the private signing schema.
-- It can read all audit tenants solely to perform complete external retention.
GRANT USAGE ON SCHEMA public, paca_audit TO paca_audit_exporter;
GRANT SELECT ON TABLE public.audit_events TO paca_audit_exporter;
GRANT SELECT, INSERT ON TABLE paca_audit.exported_events TO paca_audit_exporter;

COMMIT;
