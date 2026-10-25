#!/usr/bin/env bash
# This file is sourced by the official PostgreSQL image entrypoint when the
# Git checkout's file mode is non-executable. Keep it safe to source.
set -Eeuo pipefail

: "${PACA_RUNTIME_PASSWORD:?PACA_RUNTIME_PASSWORD is required}"
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"

psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 --set=runtime_password="$PACA_RUNTIME_PASSWORD" <<'SQL'
CREATE ROLE paca_runtime LOGIN PASSWORD :'runtime_password';
SQL
