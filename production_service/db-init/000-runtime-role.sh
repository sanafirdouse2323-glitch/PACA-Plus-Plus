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
SQL
