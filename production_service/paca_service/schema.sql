CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- The HMAC key is provisioned by the database administrator. The runtime role
-- has no schema/table access; SECURITY DEFINER verification functions read it.
CREATE SCHEMA IF NOT EXISTS paca_private;
REVOKE ALL ON SCHEMA paca_private FROM PUBLIC;
CREATE TABLE IF NOT EXISTS paca_private.tenant_context_keys (
    key_id TEXT PRIMARY KEY,
    key_material BYTEA NOT NULL CHECK (octet_length(key_material) = 32),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- CREATE SCHEMA/TABLE IF NOT EXISTS does not repair ownership on an existing
-- database. Restore both objects to the trusted migration administrator so a
-- legacy runtime owner cannot read, replace, or drop the signing-key store.
ALTER SCHEMA paca_private OWNER TO CURRENT_USER;
ALTER TABLE paca_private.tenant_context_keys OWNER TO CURRENT_USER;
REVOKE ALL ON SCHEMA paca_private FROM PUBLIC;
REVOKE ALL ON SCHEMA paca_private FROM paca_runtime;
REVOKE ALL ON TABLE paca_private.tenant_context_keys FROM PUBLIC;
REVOKE ALL ON TABLE paca_private.tenant_context_keys FROM paca_runtime;

CREATE OR REPLACE FUNCTION public.paca_constant_time_equal(
    p_expected BYTEA,
    p_supplied BYTEA
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $paca_compare$
DECLARE
    v_index INTEGER;
    v_difference INTEGER := 0;
BEGIN
    IF p_expected IS NULL OR p_supplied IS NULL
       OR octet_length(p_expected) <> 32 OR octet_length(p_supplied) <> 32 THEN
        RETURN FALSE;
    END IF;
    -- Always inspect all 32 bytes; do not exit on the first mismatch.
    FOR v_index IN 0..31 LOOP
        v_difference := v_difference
            | (get_byte(p_expected, v_index) # get_byte(p_supplied, v_index));
    END LOOP;
    RETURN v_difference = 0;
END;
$paca_compare$;
REVOKE ALL ON FUNCTION public.paca_constant_time_equal(bytea, bytea) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.paca_context_is_valid()
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $paca_context$
DECLARE
    v_tenant TEXT := nullif(current_setting('paca.ctx_tenant_id', true), '');
    v_principal TEXT := nullif(current_setting('paca.ctx_principal_id', true), '');
    v_pid TEXT := nullif(current_setting('paca.ctx_backend_pid', true), '');
    v_xid TEXT := nullif(current_setting('paca.ctx_transaction_id', true), '');
    v_issued_text TEXT := nullif(current_setting('paca.ctx_issued_at', true), '');
    v_expires_text TEXT := nullif(current_setting('paca.ctx_expires_at', true), '');
    v_key_id TEXT := nullif(current_setting('paca.ctx_key_id', true), '');
    v_signature TEXT := nullif(current_setting('paca.ctx_signature', true), '');
    v_issued BIGINT;
    v_expires BIGINT;
    v_now BIGINT;
    v_secret BYTEA;
    v_message TEXT;
BEGIN
    IF v_tenant IS NULL OR v_principal IS NULL OR v_pid IS NULL OR v_xid IS NULL
       OR v_issued_text IS NULL OR v_expires_text IS NULL OR v_key_id IS NULL
       OR v_signature IS NULL THEN
        RETURN FALSE;
    END IF;
    IF v_tenant = '' OR v_principal = '' OR length(v_tenant) > 512 OR length(v_principal) > 512
       OR position(chr(10) IN v_tenant) > 0 OR position(chr(13) IN v_tenant) > 0
       OR position(chr(10) IN v_principal) > 0 OR position(chr(13) IN v_principal) > 0
       OR v_signature !~ '^[0-9a-f]{64}$'
       OR v_key_id !~ '^[A-Za-z0-9._-]{1,32}$'
       OR v_xid !~ '^[0-9]+$' OR v_pid !~ '^[0-9]+$'
       OR v_issued_text !~ '^[0-9]+$' OR v_expires_text !~ '^[0-9]+$' THEN
        RETURN FALSE;
    END IF;

    v_issued := v_issued_text::BIGINT;
    v_expires := v_expires_text::BIGINT;
    v_now := floor(extract(epoch FROM statement_timestamp()))::BIGINT;
    IF v_issued < v_now - 60 OR v_issued > v_now + 5
       OR v_expires <= v_now OR v_expires <= v_issued
       OR v_expires > v_issued + 60 THEN
        RETURN FALSE;
    END IF;
    IF v_pid::INTEGER <> pg_backend_pid()
       OR v_xid <> pg_current_xact_id()::TEXT THEN
        RETURN FALSE;
    END IF;

    SELECT key_material INTO v_secret
    FROM paca_private.tenant_context_keys
    WHERE key_id = v_key_id AND enabled;
    IF v_secret IS NULL THEN
        RETURN FALSE;
    END IF;

    v_message := 'paca-tenant-context-v1' || chr(10) || v_tenant || chr(10)
        || v_principal || chr(10) || v_pid || chr(10) || v_xid || chr(10)
        || v_issued_text || chr(10) || v_expires_text || chr(10) || v_key_id;

    RETURN public.paca_constant_time_equal(
        public.hmac(convert_to(v_message, 'UTF8'), v_secret, 'sha256'),
        decode(v_signature, 'hex')
    );
EXCEPTION
    WHEN OTHERS THEN
        -- Invalid/malformed context is a deny, never a permissive fallback.
        RETURN FALSE;
END;
$paca_context$;

REVOKE ALL ON FUNCTION public.paca_context_is_valid() FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.paca_current_tenant_id()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $paca_tenant$
    SELECT CASE
        WHEN public.paca_context_is_valid()
        THEN nullif(current_setting('paca.ctx_tenant_id', true), '')
        ELSE NULL
    END
$paca_tenant$;

REVOKE ALL ON FUNCTION public.paca_current_tenant_id() FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.paca_set_tenant_context(
    p_tenant_id TEXT,
    p_principal_id TEXT,
    p_backend_pid INTEGER,
    p_transaction_id TEXT,
    p_issued_at BIGINT,
    p_expires_at BIGINT,
    p_key_id TEXT,
    p_signature TEXT
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $paca_set_context$
BEGIN
    PERFORM set_config('paca.ctx_tenant_id', coalesce(p_tenant_id, ''), TRUE);
    PERFORM set_config('paca.ctx_principal_id', coalesce(p_principal_id, ''), TRUE);
    PERFORM set_config('paca.ctx_backend_pid', coalesce(p_backend_pid::TEXT, ''), TRUE);
    PERFORM set_config('paca.ctx_transaction_id', coalesce(p_transaction_id, ''), TRUE);
    PERFORM set_config('paca.ctx_issued_at', coalesce(p_issued_at::TEXT, ''), TRUE);
    PERFORM set_config('paca.ctx_expires_at', coalesce(p_expires_at::TEXT, ''), TRUE);
    PERFORM set_config('paca.ctx_key_id', coalesce(p_key_id, ''), TRUE);
    PERFORM set_config('paca.ctx_signature', coalesce(p_signature, ''), TRUE);
    IF NOT public.paca_context_is_valid() THEN
        RAISE EXCEPTION 'invalid signed tenant context' USING ERRCODE = '42501';
    END IF;
END;
$paca_set_context$;

REVOKE ALL ON FUNCTION public.paca_set_tenant_context(text, text, integer, text, bigint, bigint, text, text) FROM PUBLIC;

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
    CONSTRAINT authz_permits_tenant_principal_unique
        UNIQUE (permit_id, tenant_id, principal_id),
    FOREIGN KEY (tenant_id, resource_id)
        REFERENCES protected_resources (tenant_id, resource_id)
);

ALTER TABLE protected_resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE protected_resources FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS protected_resources_tenant_isolation ON protected_resources;
CREATE POLICY protected_resources_tenant_isolation ON protected_resources
    USING (tenant_id = public.paca_current_tenant_id())
    WITH CHECK (tenant_id = public.paca_current_tenant_id());

CREATE INDEX IF NOT EXISTS authz_permits_owner_idx
    ON authz_permits (tenant_id, principal_id, created_at DESC);
CREATE INDEX IF NOT EXISTS authz_permits_expiry_idx
    ON authz_permits (status, expires_at);

CREATE TABLE IF NOT EXISTS authz_executions (
    execution_id UUID PRIMARY KEY,
    permit_id UUID NOT NULL UNIQUE,
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
    UNIQUE (tenant_id, principal_id, idempotency_key),
    CONSTRAINT authz_executions_permit_identity_fkey
        FOREIGN KEY (permit_id, tenant_id, principal_id)
        REFERENCES authz_permits (permit_id, tenant_id, principal_id)
);

-- Upgrade older schemas from a permit_id-only relationship to a tenant/principal-bound one.
-- The unique permit_id primary key means the composite key cannot collide with another permit.
DO $paca$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'public.authz_permits'::regclass
          AND conname = 'authz_permits_tenant_principal_unique'
    ) THEN
        ALTER TABLE public.authz_permits
            ADD CONSTRAINT authz_permits_tenant_principal_unique
            UNIQUE (permit_id, tenant_id, principal_id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'public.authz_executions'::regclass
          AND conname = 'authz_executions_permit_identity_fkey'
    ) THEN
        -- Add the stronger relationship before dropping the legacy FK. If legacy
        -- data is inconsistent, this fails without removing the existing guard.
        ALTER TABLE public.authz_executions
            ADD CONSTRAINT authz_executions_permit_identity_fkey
            FOREIGN KEY (permit_id, tenant_id, principal_id)
            REFERENCES public.authz_permits (permit_id, tenant_id, principal_id);
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'public.authz_executions'::regclass
          AND conname = 'authz_executions_permit_id_fkey'
    ) THEN
        ALTER TABLE public.authz_executions
            DROP CONSTRAINT authz_executions_permit_id_fkey;
    END IF;
END
$paca$;

ALTER TABLE public.authz_permits ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS authz_permits_tenant_isolation ON public.authz_permits;
CREATE POLICY authz_permits_tenant_isolation ON public.authz_permits
    USING (tenant_id = public.paca_current_tenant_id())
    WITH CHECK (tenant_id = public.paca_current_tenant_id());

ALTER TABLE public.authz_executions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS authz_executions_tenant_isolation ON public.authz_executions;
CREATE POLICY authz_executions_tenant_isolation ON public.authz_executions
    USING (tenant_id = public.paca_current_tenant_id())
    WITH CHECK (tenant_id = public.paca_current_tenant_id());

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

-- Audit rows are tenant-scoped too. Legacy/system rows with a NULL tenant are not
-- visible to the application runtime role through this policy.
ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_events_tenant_isolation ON public.audit_events;
CREATE POLICY audit_events_tenant_isolation ON public.audit_events
    USING (tenant_id = public.paca_current_tenant_id())
    WITH CHECK (tenant_id = public.paca_current_tenant_id());

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
