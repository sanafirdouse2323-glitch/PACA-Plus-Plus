CREATE TABLE IF NOT EXISTS protected_resources (
    tenant_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'inactive', 'deleted')),
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(attributes) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, resource_id)
);

CREATE TABLE IF NOT EXISTS authz_permits (
    permit_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    arguments_digest CHAR(64) NOT NULL,
    context_digest CHAR(64) NOT NULL,
    policy_revision TEXT NOT NULL,
    decision_id TEXT,
    status TEXT NOT NULL CHECK (status IN ('issued', 'executing', 'succeeded', 'failed', 'unknown', 'expired', 'revoked')),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, resource_id)
        REFERENCES protected_resources (tenant_id, resource_id)
);

ALTER TABLE protected_resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE protected_resources FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS protected_resources_tenant_isolation ON protected_resources;
CREATE POLICY protected_resources_tenant_isolation ON protected_resources
    USING (tenant_id = current_setting('paca.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('paca.tenant_id', true));

CREATE INDEX IF NOT EXISTS authz_permits_owner_idx
    ON authz_permits (tenant_id, principal_id, created_at DESC);
CREATE INDEX IF NOT EXISTS authz_permits_expiry_idx
    ON authz_permits (status, expires_at);

CREATE TABLE IF NOT EXISTS authz_executions (
    execution_id UUID PRIMARY KEY,
    permit_id UUID NOT NULL UNIQUE REFERENCES authz_permits (permit_id),
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    request_digest CHAR(64) NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('executing', 'succeeded', 'failed', 'unknown')),
    result_json JSONB,
    error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    UNIQUE (tenant_id, principal_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS authz_executions_recovery_idx
    ON authz_executions (status, started_at);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    request_id TEXT,
    tenant_id TEXT,
    principal_id TEXT,
    event_type TEXT NOT NULL,
    action TEXT,
    resource_id TEXT,
    permit_id UUID,
    execution_id UUID,
    reason_code TEXT,
    policy_revision TEXT,
    decision_id TEXT,
    arguments_digest CHAR(64),
    context_digest CHAR(64),
    details JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object')
);

CREATE INDEX IF NOT EXISTS audit_events_time_idx ON audit_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_subject_idx
    ON audit_events (tenant_id, principal_id, occurred_at DESC);

CREATE OR REPLACE FUNCTION paca_reject_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION paca_reject_audit_mutation();
