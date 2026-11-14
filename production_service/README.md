# PACA++ production-service scaffold

This directory contains a separate FastAPI authorization gateway that combines RS256 JWT verification, resource-context lookup, OPA/Rego policy decisions, PostgreSQL-backed permits and execution state, and configured file/tool/API adapters.

**Status:** controlled-evaluation scaffold. It is not production-certified and the setup instructions are not a substitute for a deployment-specific security review. For repository-wide positioning and the boundaries between this service, the prototype, compiler and agent integration, see [the architecture and scope contract](../docs/ARCHITECTURE_AND_SCOPE.md).

## Fresh local setup

1. Copy `.env.example` to `.env`. Generate three independent secrets with `openssl rand -hex 32`; put them in `POSTGRES_PASSWORD`, `PACA_RUNTIME_PASSWORD`, and `PACA_TENANT_CONTEXT_HMAC_KEY`. The first is the PostgreSQL bootstrap/admin password, the second authenticates the restricted `paca_runtime` role, and the third signs tenant context in the API and is provisioned into a private database table. Set `PACA_TENANT_CONTEXT_KEY_ID=v1` unless you are deliberately rotating keys. The checked-in example HMAC key is public test material and must be replaced.
2. Set `PACA_JWT_ISSUER`, `PACA_JWT_AUDIENCE`, and `PACA_JWT_JWKS_URL` to your actual test identity provider. The example `identity.example.org` settings are placeholders.
3. Ensure the policy revision equals `production_service/opa/data.json`. In this service, `protected_resources.owner_id` is compared with the verified OIDC `sub`; provision the owner value accordingly, and only trust role/scope/tool claims from an issuer that controls them.
4. For a newly initialized local database volume, start the stack:

   ```sh
   docker compose up --build --wait
   ```

5. Check both endpoints:

   ```sh
   curl --fail http://127.0.0.1:8000/healthz
   curl --fail http://127.0.0.1:8000/readyz
   ```

   `/healthz` only indicates that the process is alive. `/readyz` verifies PostgreSQL connectivity and signed tenant-context verification, plus a real OPA deny-by-default decision that must carry the configured policy revision.

All tenant-scoped tables (`protected_resources`, `authz_permits`, `authz_executions`, and `audit_events`) have PostgreSQL row-level-security policies that call a database-side verifier. Before each tenant-scoped operation, the API signs the tenant, verified principal, PostgreSQL backend PID, current transaction ID, issue/expiry times, and key ID with HMAC-SHA-256. PostgreSQL verifies the signature using a key in the administrator-owned `paca_private` schema, checks the backend and transaction binding, and accepts only a short-lived context (maximum 60 seconds; the API issues 30-second contexts). RLS does not trust a caller-set tenant GUC by itself. The runtime role can call the verifier/setter functions but cannot read the signing key. Execution rows retain their composite foreign key tying tenant/principal to the referenced permit. Global stale-execution recovery is an administrator-only `SECURITY DEFINER` operation. The API runtime role cannot execute it, and API startup does not run a cross-tenant recovery sweep.

**Signed-context trust boundary:** PostgreSQL custom GUCs remain mutable by a session, so the policies validate the complete signed context rather than trusting those settings. A party holding only the `paca_runtime` database credential can alter the GUC values but cannot forge a valid HMAC, read the key table, or replay a captured context in another backend/transaction. The HMAC key must be independently protected and must never be placed in SQL accessible to the runtime role, logs, tenant input, or plugins. Compromise of the API process/key, database owner/superuser, or host remains outside this control's protection. This does not provide per-principal row isolation within a tenant; application queries and OPA still enforce principal/resource authorization. Keep the runtime credential and signing key in a secrets manager in deployed environments.

**Remote OPA server-side authentication is a separate deployment requirement:** PACA++ sending `Authorization: Bearer ...` does not enable authentication on OPA. OPA's server authentication and authorization default to `off`. For a remote OPA deployment, configure OPA itself with `--authentication=token` and `--authorization=basic`, and provide a reviewed `system.authz` policy that validates the presented service token and defaults to deny. Restrict that policy to the required `POST /v1/data/paca/authz/decision` operation (plus any explicitly required operational endpoints); do not leave query, compile, policy-management or configuration APIs open. Protect the OPA listener with HTTPS, and ensure PACA verifies the OPA server certificate. Test both a valid service token and invalid/missing tokens against the actual OPA server. The private local Compose OPA is a separate trust model: it is intentionally reachable only on the internal Compose network and does not enable remote OPA authentication.

For configured HTTP effect routes, every non-2xx upstream response is treated as **outcome unknown** by default, including 4xx responses. Remote upstreams must use HTTPS and a dedicated pre-provisioned `PACA_API_BEARER_TOKEN`; remote OPA endpoints must use HTTPS and a separate `PACA_OPA_BEARER_TOKEN`. These tokens are injected credentials, not tokens automatically obtained or refreshed by PACA++. A 4xx response is not proof that no side effect occurred. A route may set `effect_not_applied_statuses` to a unique list of 400–499 status codes only when that specific upstream endpoint contract explicitly guarantees those responses are returned before any effect is applied. Review and test that contract before using the option. Do not set it merely because an error is in the 4xx range. Unknown outcomes must be reconciled with the downstream system; PACA does not automatically retry them.

The API rejects duplicate `Authorization`, `Idempotency-Key`, `Content-Length`, `Transfer-Encoding`, `Host`, and `Content-Type` headers, rejects conflicting request framing, and limits request bodies to 1 MiB. The downstream HTTP adapter streams response bodies and stops reading after its configured response-size limit. These application checks supplement rather than replace ingress-level body, concurrency, and rate limits.

The API binds to loopback on port 8000. OPA is private on the Compose control-plane network; if configuring a remote OPA endpoint, use HTTPS and set a dedicated `PACA_OPA_BEARER_TOKEN` for the gateway. Do not reuse an end-user token. Configured remote effect routes likewise require HTTPS and a dedicated `PACA_API_BEARER_TOKEN`. Do not expose the API externally before configuring and validating TLS ingress, rate/request limits, secrets management, egress controls, backups/restore, audit retention, monitoring, and incident response.

## Real OIDC provider configuration

The gateway validates access tokens against one explicit OIDC issuer, audience, and JWKS URI. The values in `.env.example` are deliberately non-working placeholders, not deployment credentials or a configured external tenant. Before using a real provider, replace all three with values from the provider's own OpenID Connect discovery document.

For a Keycloak realm named `paca`, obtain `issuer` and `jwks_uri` from:

```text
https://YOUR-KEYCLOAK-HOST/realms/paca/.well-known/openid-configuration
```

Set:
- `PACA_JWT_ISSUER` to the exact `issuer` value in that document (including path and trailing-slash behavior exactly as published).
- `PACA_JWT_JWKS_URL` to the exact `jwks_uri` value in that document.
- `PACA_JWT_AUDIENCE` to the API audience configured in the access token; in the example below this is `paca-api`.

The provider must issue **RS256-signed access tokens** with `sub`, `iss`, `aud`, `exp`, `iat`, a trusted `tenant_id` claim, and the configured access-only marker (by default `token_use=access`). The marker must not appear in ID tokens. The service also reads optional string-list `roles` and `tools` claims, and authorization scopes from a string-list `scopes` claim or the standard space-delimited `scope` claim. Do not accept tenant membership or privileged roles from user-editable profile fields. Provision/map them through administrator-controlled identity attributes, groups, app roles, or an equivalent trusted authorization source. The OPA policy in this repository currently expects the resource owner to equal the verified token's `sub` (unless a trusted `admin` role applies).

See [IDENTITY_PROVIDER.md](IDENTITY_PROVIDER.md) for the provider claim contract, production client setup guidance, and the end-to-end verification performed against Keycloak.

### Live identity integration test

CI starts a real Keycloak server with the isolated test realm in `tests/identity/keycloak-realm.json`. The integration test fetches its live OIDC discovery document, requests access tokens from its token endpoint, verifies those tokens through the real JWKS endpoint, and sends them through the actual FastAPI authorization endpoint, PostgreSQL permit/execution store, OPA policy engine, and sandboxed file adapter. It checks successful execution/status, wrong-audience rejection, cross-tenant isolation, and same-tenant owner denial.

Run the targeted check only while a Keycloak test realm, OPA, and an **isolated disposable PostgreSQL test database** are reachable from the test process. Set both database DSNs first: `PACA_TEST_ADMIN_DATABASE_URL` must use the test database's administrative/fixture-provisioning role, and `PACA_TEST_DATABASE_URL` must use the restricted runtime role. The test intentionally skips if either DSN is absent; a skipped test is not a successful OIDC integration test.

```sh
export PACA_TEST_ADMIN_DATABASE_URL='<admin DSN for disposable test database>'
export PACA_TEST_DATABASE_URL='<restricted runtime DSN for the same test database>'
export PACA_TENANT_CONTEXT_HMAC_KEY="$(openssl rand -hex 32)"
export PACA_TENANT_CONTEXT_KEY_ID=v1
PACA_TEST_OIDC_REALM_URL=http://localhost:8081/realms/paca \
PACA_TEST_OPA_URL=http://127.0.0.1:8181 \
pytest tests/test_oidc_integration.py -q
```

Replace the quoted DSN examples with valid connection URLs; do not point this test at a production database. Provision the same HMAC key into `paca_private.tenant_context_keys` through the administrative connection before running the PostgreSQL tests. The CI workflow provisions an isolated PostgreSQL service with the separate administrative and restricted runtime credentials and runs this end-to-end test explicitly.

The committed test realm is **for automated local/CI testing only**. It uses HTTP, test-only confidential client secrets, service-account identities, client-credentials tokens, and hard-coded demonstration claims. Do not reuse those credentials or hard-coded permissions in production. For production, deploy Keycloak in a supported secure mode behind HTTPS, use a public client with Authorization Code + PKCE for interactive applications, configure the API audience mapper and administrator-controlled tenant/role/scope mappings, and issue the required access-only `token_use=access` marker. Use short-lived access tokens. A successful local/CI flow is integration evidence, not proof that an external organization's tenant has been provisioned or that its policies are correct.

## Stale execution recovery (administrator-only)

The API deliberately does not run global stale-execution recovery with its restricted runtime credential. This avoids giving a stolen `paca_runtime` credential a cross-tenant state-transition capability. If an operator needs to classify executions left in `executing` after a crash, first investigate downstream effects and choose a threshold longer than the maximum legitimate execution duration, with an appropriate reconciliation margin. Then run the database function using an administrator-owned connection:

```sh
psql "$PACA_ADMIN_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -c "SELECT public.paca_mark_stale_executions_unknown(120);"
```

Replace `120` with the reviewed threshold in seconds. The function marks every qualifying stale execution and its permit as `unknown`; it does not retry the external effect. The function is intentionally executable only by its database owner/administrator, not by `paca_runtime`. Treat this as a privileged operational action and retain the resulting audit events.

## HMAC key rotation

The key ID selects a row in `paca_private.tenant_context_keys`. To rotate without invalidating in-flight requests, provision a new key under a new ID first, deploy the matching key and ID to every API instance, wait at least 60 seconds after the last old-key request, then disable the old key with an administrator-only statement such as `UPDATE paca_private.tenant_context_keys SET enabled = FALSE WHERE key_id = 'old-id';`. Never reuse a key ID for different key material while old API instances may still be active. Keep both the database copy and API copy in a secrets manager; the example `.env` workflow is for local evaluation only.

## Upgrading an existing volume safely

The official PostgreSQL image runs `/docker-entrypoint-initdb.d/` scripts only when initializing an **empty** data directory. Editing `.env` and restarting does not create `paca_runtime` or reapply grants to an existing volume.

Before upgrading, take and verify a database backup. Keep the existing data volume. With the old database administrator still available, update `.env` with a strong `PACA_RUNTIME_PASSWORD`, `PACA_TENANT_CONTEXT_HMAC_KEY`, and `PACA_TENANT_CONTEXT_KEY_ID`. Recreate the database container so it receives the new environment, then run these commands from `production_service/`:

```sh
docker compose stop api
docker compose up -d --force-recreate database
docker compose exec database bash -lc 'source /docker-entrypoint-initdb.d/000-runtime-role.sh'
docker compose exec -T database psql -U paca -d paca -v ON_ERROR_STOP=1 -f /docker-entrypoint-initdb.d/001-schema.sql
docker compose exec -T database psql -U paca -d paca -v ON_ERROR_STOP=1 -f /docker-entrypoint-initdb.d/002-runtime-grants.sql
docker compose exec database bash -lc 'source /docker-entrypoint-initdb.d/003-tenant-context-key.sh'
docker compose up --build -d
```

The role-creation script is idempotent so it can be rerun for a controlled upgrade; it also removes every direct role membership from an existing `paca_runtime` role, because `NOINHERIT` alone does not prevent `SET ROLE`. The grants migration explicitly reassigns the `SECURITY DEFINER` functions to the trusted migration administrator because `CREATE OR REPLACE FUNCTION` does not change an existing function's owner. The schema migration replaces the old GUC-only RLS policies with signed-context verification. The grants migration exposes only the verifier/setter functions to the runtime role and explicitly revokes any legacy runtime grant on global recovery; the final command provisions the HMAC key. Do not start the updated API until the key row exists and the runtime grants are applied. If the old database administrator credential is unavailable, stop and recover access before changing roles. **Do not run `docker compose down -v`** to solve a permission error: that deletes persistent volumes.

## Test and lint

From this directory:

```sh
python -m pip install -e ".[dev]"
pytest -q
ruff check .
```

PostgreSQL integration tests need both `PACA_TEST_DATABASE_URL` (restricted runtime role) and `PACA_TEST_ADMIN_DATABASE_URL` (fixture/schema administration). If either is missing, those tests are skipped; skipped tests are not passing database tests.

## Residual limits

- Compose is for local evaluation, not a production deployment recipe.
- Remote PostgreSQL must use `sslmode=verify-full`; remote OPA and downstream HTTP endpoints must use HTTPS.
- The runtime role cannot provision or alter trusted resource facts. An administrator-controlled process must provision them.
- PostgreSQL cannot atomically commit an arbitrary external API effect. On ambiguous outcomes, the service records `unknown` and does not blindly retry; downstream idempotency/reconciliation remains required.
- An in-database append-only trigger is not immutable against an owner or superuser. Export audit events to independently controlled retention-protected storage.
- Passing CI is not a penetration test, formal proof, independent audit, external benchmark, standards-compliance claim, or proof of research novelty.

See [THREAT_MODEL.md](THREAT_MODEL.md) for trust boundaries and deployment gates.
