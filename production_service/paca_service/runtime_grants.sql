-- Apply as the schema owner / migration administrator after schema.sql.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON protected_resources, authz_permits, authz_executions, audit_events FROM PUBLIC;
REVOKE ALL ON SEQUENCE audit_events_event_id_seq FROM PUBLIC;
REVOKE ALL ON FUNCTION public.paca_reject_audit_mutation() FROM PUBLIC;

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
    WHERE p_tenant_id = current_setting('paca.tenant_id', true)
      AND pr.tenant_id = p_tenant_id
      AND pr.resource_id = p_resource_id
    FOR SHARE
$paca_lock$;

REVOKE ALL ON FUNCTION public.paca_lock_resource_for_execution(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.paca_lock_resource_for_execution(text, text) TO paca_runtime;

-- The startup recovery sweep is the only cross-tenant operation exposed to the
-- application role. Keep it in a bounded SECURITY DEFINER function owned by the
-- schema owner; ordinary runtime queries remain subject to tenant RLS policies.
CREATE OR REPLACE FUNCTION public.paca_mark_stale_executions_unknown(
    p_stale_after_seconds integer
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $paca_recovery$
DECLARE
    stale_row record;
    changed_count integer := 0;
BEGIN
    IF p_stale_after_seconds IS NULL
       OR p_stale_after_seconds < 1
       OR p_stale_after_seconds > 86400 THEN
        RAISE EXCEPTION 'stale threshold must be between 1 and 86400 seconds'
            USING ERRCODE = '22023';
    END IF;

    FOR stale_row IN
        UPDATE public.authz_executions AS e
        SET status = 'unknown',
            error_code = 'stale_execution_recovered',
            finished_at = now()
        WHERE e.status = 'executing'
          AND e.started_at < now() - make_interval(secs => p_stale_after_seconds)
        RETURNING e.execution_id, e.permit_id, e.tenant_id, e.principal_id
    LOOP
        UPDATE public.authz_permits AS p
        SET status = 'unknown', updated_at = now()
        WHERE p.permit_id = stale_row.permit_id
          AND p.tenant_id = stale_row.tenant_id
          AND p.principal_id = stale_row.principal_id;

        INSERT INTO public.audit_events (
            tenant_id, principal_id, event_type, permit_id, execution_id, reason_code
        ) VALUES (
            stale_row.tenant_id, stale_row.principal_id, 'execution_unknown',
            stale_row.permit_id, stale_row.execution_id, 'stale_execution_recovered'
        );
        changed_count := changed_count + 1;
    END LOOP;
    RETURN changed_count;
END;
$paca_recovery$;

REVOKE ALL ON FUNCTION public.paca_mark_stale_executions_unknown(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.paca_mark_stale_executions_unknown(integer) TO paca_runtime;

GRANT USAGE ON SCHEMA public TO paca_runtime;
-- Resource records are provisioned by a trusted administrative process.
-- The API runtime may read records but must not create or alter authorization facts.
GRANT SELECT ON protected_resources TO paca_runtime;
GRANT SELECT, INSERT, UPDATE ON authz_permits TO paca_runtime;
GRANT SELECT, INSERT, UPDATE ON authz_executions TO paca_runtime;
GRANT SELECT, INSERT ON audit_events TO paca_runtime;
GRANT USAGE, SELECT ON SEQUENCE audit_events_event_id_seq TO paca_runtime;
