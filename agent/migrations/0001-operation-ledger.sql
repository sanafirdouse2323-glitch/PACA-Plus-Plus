-- Dedicated transactional journal for PACA++ LangGraph protected operations.
-- Apply with a migration/owner role in the dedicated LangGraph persistence database.
BEGIN;

CREATE SCHEMA IF NOT EXISTS paca_langgraph;
REVOKE ALL ON SCHEMA paca_langgraph FROM PUBLIC;

CREATE TABLE IF NOT EXISTS paca_langgraph.execution_journal (
    thread_hash CHAR(64) NOT NULL CHECK (thread_hash ~ '^[0-9a-f]{64}$'),
    tool_call_hash CHAR(64) NOT NULL CHECK (tool_call_hash ~ '^[0-9a-f]{64}$'),
    tool_name VARCHAR(64) NOT NULL,
    action VARCHAR(128) NOT NULL,
    request_fingerprint CHAR(64) NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    permit_id UUID NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('authorized', 'succeeded', 'failed', 'unknown')),
    result_json JSONB,
    execution_id TEXT,
    lease_owner UUID,
    lease_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (thread_hash, tool_call_hash),
    CONSTRAINT execution_journal_idempotency_key_format
        CHECK (idempotency_key ~ '^[A-Za-z0-9._~-]{1,128}$'),
    CONSTRAINT execution_journal_terminal_result
        CHECK (
            (status = 'authorized' AND result_json IS NULL AND execution_id IS NULL)
            OR (status IN ('succeeded', 'failed', 'unknown') AND result_json IS NOT NULL)
        ),
    CONSTRAINT execution_journal_lease_pair
        CHECK (
            (lease_owner IS NULL AND lease_expires_at IS NULL)
            OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL AND status = 'authorized')
        )
);

CREATE INDEX IF NOT EXISTS execution_journal_updated_idx
    ON paca_langgraph.execution_journal (updated_at);

REVOKE ALL ON TABLE paca_langgraph.execution_journal FROM PUBLIC;

COMMIT;
