-- Apply as the schema owner / migration administrator after schema.sql.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON protected_resources, authz_permits, authz_executions, audit_events FROM PUBLIC;
REVOKE ALL ON SEQUENCE audit_events_event_id_seq FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO paca_runtime;
-- Resource records are provisioned by a trusted administrative process.
-- The API runtime may read records but must not create or alter authorization facts.
GRANT SELECT ON protected_resources TO paca_runtime;
GRANT SELECT, INSERT, UPDATE ON authz_permits TO paca_runtime;
GRANT SELECT, INSERT, UPDATE ON authz_executions TO paca_runtime;
GRANT SELECT, INSERT ON audit_events TO paca_runtime;
GRANT USAGE, SELECT ON SEQUENCE audit_events_event_id_seq TO paca_runtime;
