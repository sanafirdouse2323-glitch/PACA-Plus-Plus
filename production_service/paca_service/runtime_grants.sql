REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON protected_resources, authz_permits, authz_executions, audit_events FROM PUBLIC;
REVOKE ALL ON SEQUENCE audit_events_event_id_seq FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO paca_runtime;
GRANT SELECT ON protected_resources TO paca_runtime;
GRANT SELECT, INSERT, UPDATE ON authz_permits TO paca_runtime;
GRANT SELECT, INSERT, UPDATE ON authz_executions TO paca_runtime;
GRANT INSERT ON audit_events TO paca_runtime;
GRANT USAGE, SELECT ON SEQUENCE audit_events_event_id_seq TO paca_runtime;
