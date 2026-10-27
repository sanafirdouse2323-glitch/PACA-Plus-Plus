# PACA++ production-service scaffold

This directory contains a separate FastAPI authorization gateway that combines RS256 JWT verification, resource-context lookup, OPA/Rego policy decisions, PostgreSQL-backed permits and execution state, and configured file/tool/API adapters.

**Status:** controlled-evaluation scaffold. It is not production-certified and the setup instructions are not a substitute for a deployment-specific security review.

## Fresh local setup

1. Copy `.env.example` to `.env`. Generate two independent secrets with `openssl rand -hex 32`; put one in `POSTGRES_PASSWORD` and the other in `PACA_RUNTIME_PASSWORD`. PostgreSQL's bootstrap/admin account uses the first; the API uses a restricted `paca_runtime` account.
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

   `/healthz` only indicates that the process is alive. `/readyz` verifies database connectivity and a real OPA deny-by-default decision that must carry the configured policy revision.

All tenant-scoped tables (`protected_resources`, `authz_permits`, `authz_executions`, and `audit_events`) have PostgreSQL row-level-security policies. The runtime store sets transaction-local `paca.tenant_id` before every tenant-scoped query, and execution rows have a composite foreign key tying tenant/principal to the referenced permit. Stale-execution recovery is the only cross-tenant store operation exposed to the runtime role; it uses a bounded, audited `SECURITY DEFINER` function rather than an unscoped application query.

**RLS trust boundary:** `paca.tenant_id` is a custom PostgreSQL setting, not a database-authenticated identity. These policies protect against omitted tenant predicates and alternate application query paths while the trusted application controls the transaction. A party holding the raw runtime database credential can set that custom setting itself; do not expose the credential to tenants or untrusted plugins. If the threat model includes malicious SQL under that credential, use a stronger separation model such as distinct tenant database roles/databases or a trusted database-access broker.

The API rejects duplicate `Authorization`, `Idempotency-Key`, `Content-Length`, `Transfer-Encoding`, `Host`, and `Content-Type` headers, rejects conflicting request framing, and limits request bodies to 1 MiB. The downstream HTTP adapter streams response bodies and stops reading after its configured response-size limit. These application checks supplement rather than replace ingress-level body, concurrency, and rate limits.

The API binds to loopback on port 8000. Do not expose it externally before configuring and validating TLS ingress, rate/request limits, secrets management, egress controls, backups/restore, audit retention, monitoring, and incident response.

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

The provider must issue **RS256-signed access tokens** with `sub`, `iss`, `aud`, `exp`, `iat`, and a trusted `tenant_id` claim. The service also reads optional string-list `roles` and `tools` claims, and authorization scopes from a string-list `scopes` claim or the standard space-delimited `scope` claim. Do not accept tenant membership or privileged roles from user-editable profile fields. Provision/map them through administrator-controlled identity attributes, groups, app roles, or an equivalent trusted authorization source. The OPA policy in this repository currently expects the resource owner to equal the verified token's `sub` (unless a trusted `admin` role applies).

See [IDENTITY_PROVIDER.md](IDENTITY_PROVIDER.md) for the provider claim contract, production client setup guidance, and the end-to-end verification performed against Keycloak.

### Live identity integration test

CI starts a real Keycloak server with the isolated test realm in `tests/identity/keycloak-realm.json`. The integration test fetches its live OIDC discovery document, requests access tokens from its token endpoint, verifies those tokens through the real JWKS endpoint, and sends them through the actual FastAPI authorization endpoint, PostgreSQL permit/execution store, OPA policy engine, and sandboxed file adapter. It checks successful execution/status, wrong-audience rejection, cross-tenant isolation, and same-tenant owner denial.

Run the targeted check only while a Keycloak test realm, OPA, and an **isolated disposable PostgreSQL test database** are reachable from the test process. Set both database DSNs first: `PACA_TEST_ADMIN_DATABASE_URL` must use the test database's administrative/fixture-provisioning role, and `PACA_TEST_DATABASE_URL` must use the restricted runtime role. The test intentionally skips if either DSN is absent; a skipped test is not a successful OIDC integration test.

```sh
export PACA_TEST_ADMIN_DATABASE_URL='<admin DSN for disposable test database>'
export PACA_TEST_DATABASE_URL='<restricted runtime DSN for the same test database>'
PACA_TEST_OIDC_REALM_URL=http://localhost:8081/realms/paca \
PACA_TEST_OPA_URL=http://127.0.0.1:8181 \
pytest tests/test_oidc_integration.py -q
```

Replace the two quoted DSN examples with valid connection URLs; do not point this test at a production database. The CI workflow provisions an isolated PostgreSQL service with the separate administrative and restricted runtime credentials and runs this end-to-end test explicitly.

The committed test realm is **for automated local/CI testing only**. It uses HTTP, a test user/password, password-grant authentication, and a hard-coded demonstration scope claim. Do not reuse those credentials, password grant, or hard-coded permissions in production. For production, deploy Keycloak in a supported secure mode behind HTTPS, use a public client with Authorization Code + PKCE for interactive applications, configure the API audience mapper and administrator-controlled tenant/role/scope mappings, and use short-lived access tokens. A successful local/CI flow is integration evidence, not proof that an external organization's tenant has been provisioned or that its policies are correct.

## Upgrading an existing volume safely

The official PostgreSQL image runs `/docker-entrypoint-initdb.d/` scripts only when initializing an **empty** data directory. Editing `.env` and restarting does not create `paca_runtime` or reapply grants to an existing volume.

Before upgrading, take and verify a database backup. Keep the existing data volume. With the old database administrator still available, update `.env` with a strong `PACA_RUNTIME_PASSWORD`, then run these commands from `production_service/`:

```sh
docker compose exec database bash -lc 'source /docker-entrypoint-initdb.d/000-runtime-role.sh'
docker compose exec -T database psql -U paca -d paca -v ON_ERROR_STOP=1 -f /docker-entrypoint-initdb.d/001-schema.sql
docker compose exec -T database psql -U paca -d paca -v ON_ERROR_STOP=1 -f /docker-entrypoint-initdb.d/002-runtime-grants.sql
docker compose up --build -d
```

The role-creation script is idempotent so it can be rerun for a controlled upgrade. The second command reapplies the grants. If the old database administrator credential is unavailable, stop and recover access before changing roles. **Do not run `docker compose down -v`** to solve a permission error: that deletes persistent volumes.

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
