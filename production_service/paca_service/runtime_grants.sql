GRANT USAGE ON SCHEMA public TO paca_runtime;
GRANT SELECT ON protected_resources TO paca_runtime;
GRANT SELECT, INSERT, UPDATE ON authz_permits TO paca_runtime;
GRANT SELECT, INSERT, UPDATE ON authz_executions TO paca_runtime;
GRANT INSERT ON audit_events TO paca_runtime;
GRANT USAGE, SELECT ON SEQUENCE audit_events_event_id_seq TO paca_runtime;
