-- DEVELOPMENT ONLY. Do not apply this file in production.
INSERT INTO protected_resources
    (tenant_id, resource_id, owner_id, kind, status, attributes)
VALUES
    ('demo-tenant', 'demo-document', 'demo-user', 'document', 'active', '{}'::jsonb),
    ('demo-tenant', 'demo-file', 'demo-user', 'file', 'active',
     '{"relative_path":"report.txt"}'::jsonb),
    ('demo-tenant', 'demo-tool', 'demo-user', 'tool', 'active', '{}'::jsonb)
ON CONFLICT (tenant_id, resource_id) DO NOTHING;
