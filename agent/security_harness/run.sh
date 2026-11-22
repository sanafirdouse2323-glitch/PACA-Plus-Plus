#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${RUNNER_TEMP:-/tmp}/paca-host-isolation-certs"
mkdir -p "${CERT_DIR}"
chmod 700 "${CERT_DIR}"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -keyout "${CERT_DIR}/server.key" \
  -out "${CERT_DIR}/server.crt" \
  -subj "/CN=paca-gateway" \
  -addext "subjectAltName=DNS:paca-gateway" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "extendedKeyUsage=serverAuth"
chmod 644 "${CERT_DIR}/server.key"  # Ephemeral test key for the mock gateway only.
export PACA_HARNESS_CERT_DIR="${CERT_DIR}"

cd "${SCRIPT_DIR}"
docker compose -f compose.yaml down --volumes --remove-orphans >/dev/null 2>&1 || true
cleanup() {
  docker compose -f compose.yaml down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose -f compose.yaml up --build \
  --abort-on-container-exit --exit-code-from agent-host
