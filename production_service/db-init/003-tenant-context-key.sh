#!/usr/bin/env bash
# Provision/update the HMAC key using the database administrator connection.
set -Eeuo pipefail

: "${PACA_TENANT_CONTEXT_HMAC_KEY:?PACA_TENANT_CONTEXT_HMAC_KEY is required}"
: "${PACA_TENANT_CONTEXT_KEY_ID:=v1}"
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"

if [[ ! "$PACA_TENANT_CONTEXT_HMAC_KEY" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "PACA_TENANT_CONTEXT_HMAC_KEY must be exactly 64 hexadecimal characters" >&2
  exit 1
fi
if [[ ! "$PACA_TENANT_CONTEXT_KEY_ID" =~ ^[A-Za-z0-9._-]{1,32}$ ]]; then
  echo "PACA_TENANT_CONTEXT_KEY_ID must be a 1-32 character safe identifier" >&2
  exit 1
fi

psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 \
  --set=context_key_id="$PACA_TENANT_CONTEXT_KEY_ID" \
  --set=context_key="$PACA_TENANT_CONTEXT_HMAC_KEY" <<'SQL'
INSERT INTO paca_private.tenant_context_keys (key_id, key_material, enabled)
VALUES (:'context_key_id', decode(:'context_key', 'hex'), TRUE)
ON CONFLICT (key_id) DO UPDATE
SET key_material = EXCLUDED.key_material, enabled = TRUE;
SQL
