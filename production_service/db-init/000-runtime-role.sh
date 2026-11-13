#!/usr/bin/env bash
# The official PostgreSQL image sources this file when its Git mode is not executable.
# Keep it safe to source in the entrypoint shell.
set -Eeuo pipefail

: "${PACA_RUNTIME_PASSWORD:?PACA_RUNTIME_PASSWORD is required}"
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"

# Idempotent so an administrator can re-run this after backing up an existing volume.
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 --set=runtime_password="$PACA_RUNTIME_PASSWORD" <<'SQL'
SELECT format(
  'CREATE ROLE paca_runtime LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT',
  :'runtime_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paca_runtime')
\gexec
ALTER ROLE paca_runtime LOGIN PASSWORD :'runtime_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;

-- A pre-existing runtime role may have been granted membership in another
-- role. NOINHERIT alone is insufficient because membership can still permit
-- SET ROLE. Remove every direct membership before granting application access.
DO $paca_revoke_memberships$
DECLARE
  granted_role record;
BEGIN
  FOR granted_role IN
    SELECT granted.rolname
    FROM pg_auth_members AS membership
    JOIN pg_roles AS granted ON granted.oid = membership.roleid
    JOIN pg_roles AS member ON member.oid = membership.member
    WHERE member.rolname = 'paca_runtime'
  LOOP
    EXECUTE format('REVOKE %I FROM paca_runtime', granted_role.rolname);
  END LOOP;
END
$paca_revoke_memberships$;

-- A direct database CREATE grant (including one inherited from PUBLIC) would
-- let the runtime role pre-create security-sensitive schemas. Remove it as
-- well as role memberships; CREATE ROLE attributes do not revoke ACL grants.
DO $paca_revoke_database_create$
BEGIN
  EXECUTE format('REVOKE CREATE ON DATABASE %I FROM paca_runtime', current_database());
  EXECUTE 'REVOKE CREATE ON DATABASE ' || quote_ident(current_database()) || ' FROM PUBLIC';
END
$paca_revoke_database_create$;
SQL
