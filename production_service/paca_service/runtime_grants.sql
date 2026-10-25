-- Apply as the schema owner / migration administrator after schema.sql.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON protected_resources, authz_permits, authz_executions, audit_events FROM PUBLIC;
REVOKE ALL ON SEQUENCE audit_events_event_id_seq FROM PUBLIC;

-- Lock trusted resource rows for the duration of an execution-claim transaction
-- without granting the API UPDATE privilege on the resource table.
CREATE OR REPLACE FUNCTION public.paca_lock_resource_for_execution(
    p_tenant_id text,
    p_resource_id text
)
RETURNS TABLE (
    tenant_id text,
    resource_id text,
    owner_id text,
    kind text,
    status text,
    attributes jsonb
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $paca_lock$
    SELECT pr.tenant_id, pr.resource_id, pr.owner_id, pr.kind, pr.status, pr.attributes
    FROM public.protected_resources AS pr
    WHERE pr.tenant_id = p_tenant_id
      AND pr.resource_id = p_resource_id
    FOR SHARE
$paca_lock$;

REVOKE ALL ON FUNCTION public.paca_lock_resource_for_execution(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.paca_lock_resource_for_execution(text, text) TO paca_runtime;

GRANT USAGE ON SCHEMA public TO paca_runtime;
-- Resource records are provisioned by a trusted administrative process.
-- The API runtime may read records but must not create or alter authorization facts.
GRANT SELECT ON protected_resources TO paca_runtime;
GRANT SELECT, INSERT, UPDATE ON authz_permits TO paca_runtime;
GRANT SELECT, INSERT, UPDATE ON authz_executions TO paca_runtime;
GRANT SELECT, INSERT ON audit_events TO paca_runtime;
GRANT USAGE, SELECT ON SEQUENCE audit_events_event_id_seq TO paca_runtime;
