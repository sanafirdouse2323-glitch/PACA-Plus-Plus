-- PACA++ trusted authorization-context reference schema, migration 002.
-- Provision data through a separate administrator-controlled process. The
-- context service has no mutation routes and should receive SELECT-only grants.
BEGIN;

CREATE TABLE IF NOT EXISTS paca_context_principals (
    principal_id TEXT NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 512),
    issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
    audience TEXT NOT NULL CHECK (length(audience) BETWEEN 1 AND 512),
    tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 512),
    role TEXT NOT NULL CHECK (length(role) BETWEEN 1 AND 128),
    can_create_tickets BOOLEAN NOT NULL DEFAULT FALSE,
    suspended BOOLEAN NOT NULL DEFAULT FALSE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (issuer, subject, audience, tenant_id),
    UNIQUE (principal_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS paca_context_principal_id_idx
    ON paca_context_principals (principal_id);

CREATE TABLE IF NOT EXISTS paca_context_resources (
    resource TEXT PRIMARY KEY CHECK (length(resource) BETWEEN 1 AND 512),
    tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 512),
    owner_principal_id TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT paca_context_resource_owner_fk
        FOREIGN KEY (owner_principal_id, tenant_id)
        REFERENCES paca_context_principals (principal_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS paca_context_resource_tenant_idx
    ON paca_context_resources (tenant_id);

COMMIT;
