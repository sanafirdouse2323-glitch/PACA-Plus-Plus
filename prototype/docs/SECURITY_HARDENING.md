# PACA++ hardening layer: architecture, configuration, and claims

## What this branch adds

The legacy **AuthorizationEngine** remains an in-memory, single-process research MVP. This branch adds a separate integration path and a runnable ASGI endpoint for a single, allowlisted `ticket.create` action, without silently rewriting the original ALFA/UCON+ compiler work:

- **Policy decision point:** **OPAClient** calls a named Open Policy Agent (OPA) Data API decision. An absent/malformed decision, missing permit version, timeout, HTTP error, or transport failure raises an error; the gateway does not treat that as permission.
- **Policy version recheck:** an allowed decision carries a version. The gateway asks OPA for the active version immediately before the effect and rejects a mismatch. This narrows, but cannot atomically eliminate, the race with policy reload; coordinate policy deployments with effect commits where that matters.
- **Authentication:** **OIDCJWTIdentityProvider** verifies RS256 JWT signatures using a configured HTTPS JWKS endpoint and validates issuer, audience, expiry, and required claims. It never accepts merely decoded tokens. It is an adapter, not an identity provider or credential issuer.
- **Trusted context:** **HTTPAuthorizationContextProvider** obtains contextual attributes from an administrator-configured HTTPS service using a separate service credential. Request-supplied roles/attributes must not be substituted for the result. The gateway rejects a context response that tries to overwrite verified identity.
- **Reference context service:** `paca_mvp.context_service` exposes a read-only, service-token-protected endpoint backed by administrator-managed PostgreSQL tables. It maps the verified issuer/subject/audience to an internal principal *within the registered resource's tenant*, then returns current role, capability, suspension state, and internal resource ownership. Unmapped/inactive identities and unknown resources receive deny-only context. There are no identity/role mutation endpoints and no default users or resources.
- **Enforcement adapters:** **FilesystemToolAdapter** maps administrator-defined logical resource IDs to a fixed local root and uses POSIX descriptor-relative, no-follow traversal. **HTTPJSONToolAdapter** can call only administrator-configured action/resource routes over HTTPS, blocks redirects, and sends a downstream idempotency key.
- **Coordinated durable state:** **SQLitePermitStore** persists short-lived permits, state versions, execution claims, idempotency keys, results, and audit events in a file-backed SQLite database. SQLite transactions serialize local processes sharing that file on the same machine; this is not a distributed database for multi-host coordination.
- **Failure and replay behavior:** the store claims an operation durably before invoking an adapter. If a process crashes or an adapter raises after a possible partial side effect, the operation becomes/should be reconciled as **unknown**; the system does not automatically replay it. A downstream service that durably honors the idempotency key or exposes reconciliation is required to safely resume.
- **Audit integrity checking:** events are persisted with a hash-linked chain and a separately stored head. **verify_audit_chain()** checks event hashes, links, and the stored head, detecting changed events and tail truncation when the head is left intact. Appends are refused if the stored head does not match the actual last event; PostgreSQL initialization/migration backfills a missing head from retained history. This is **not tamper-proof** against an attacker who can rewrite the database and its head. Production audit should also be streamed to an independently controlled append-only system.
- **HTTP request-boundary checks:** the ASGI size-limit middleware preserves duplicate headers until validation and rejects duplicate `Authorization`/`Idempotency-Key` headers on the ticket route, duplicate framing/host/content-type headers, and requests that combine `Content-Length` with `Transfer-Encoding`. This reduces ambiguity between upstream proxies and application header parsing; it does not replace equivalent validation at the load balancer and HTTP server.
- **Adversarial checks:** the new test file covers OPA failures, malformed decisions, stale policy/state, expired permits, repeated idempotency keys, effect failures, crash recovery, concurrent execution, symlink traversal, fixed API routes, and audit-chain tampering.

## Run locally

Requires Python 3.10+ and Docker for the OPA and PostgreSQL integration services. Install the optional `web` extra to run the ASGI gateway.

~~~bash
cd prototype
python -m pip install -e ".[web,test]"
python -m unittest discover -s tests -v
python examples/demo.py
python experiments/run_experiments.py
docker compose up -d opa
docker compose --profile integration up -d postgres
python examples/opa_smoke.py
docker compose down
~~~

The OPA and PostgreSQL Compose ports are bound to loopback. PostgreSQL is enabled only by the `integration` profile; the example database password is for local tests only. The example Rego policy permits an analyst to read only a resource owned by the verified internal principal in the same tenant; it does not compare raw OIDC subjects to ownership IDs. It permits ticket creation only when a trusted context grants the support role and explicit capability in the registered resource tenant, and requires `suspended=false`. A signed JWT claim that explicitly says suspended still triggers a deny, but current suspension comes from trusted context so a stale token claim cannot override it. The policy is illustrative, not universal production policy. Increment **policy_version** whenever authorization semantics change; production bundle deployments should tie this to an immutable, verified bundle revision and coordinate rollout.

## Run the HTTP gateway

1. Configure a real OIDC issuer, audience and JWKS endpoint, OPA, a downstream HTTPS API and its idempotency semantics in `.env` using `.env.example` as a template. Never commit real secrets. The reference context service can be started with `uvicorn paca_mvp.context_service:create_context_app --factory --host 127.0.0.1 --port 8081`; for local-only testing set `PACA_CONTEXT_URL=http://127.0.0.1:8081/v1/attributes` and explicitly set `PACA_CONTEXT_ALLOW_INSECURE_LOCALHOST=true`. Do not enable that flag for non-loopback URLs or production.
2. Start local OPA and PostgreSQL: `docker compose up -d opa` and `docker compose --profile integration up -d postgres`. To apply all numbered migrations, set `PACA_MIGRATION_DSN` to the intended database URL and run `python examples/apply_postgres_migration.py`; applied versions are recorded in `paca_schema_migrations`. Migration 002 creates the reference context tables but inserts no users, capabilities, suspension state, or resources. Provision these through a separate controlled administrator process. In production, use distinct migration, permit-store, and read-only context-service database roles; keep `PACA_DATABASE_AUTO_MIGRATE=false` for the gateway runtime. Non-loopback PostgreSQL DSNs must use `sslmode=verify-full`.
3. Load your environment in the shell (for example, `set -a; . ./.env; set +a`) and run `uvicorn paca_mvp.service:create_app --factory --host 127.0.0.1 --port 8080`.
4. Call `POST /v1/tickets` with a valid `Authorization: Bearer ...`, a stable `Idempotency-Key`, and a JSON body such as `{"title":"Example","description":"Details" }`. The endpoint fixes the action/resource itself; callers cannot choose the adapter, URL or route.
5. Use `GET /readyz` to check OPA and database readiness. It is not a substitute for downstream/context-service health checks.

The configured downstream endpoint receives the ticket argument object as ordinary JSON and the standard `Idempotency-Key` header. The downstream API must durably implement that key; this gateway cannot impose idempotency semantics on a third-party service.

## Typical application wiring

Use deployment-managed secrets and configuration, not values supplied by an agent:

~~~python
import os
from paca_mvp import (
    OPAClient, SQLitePermitStore, GuardedGateway,
    OIDCJWTIdentityProvider, HTTPAuthorizationContextProvider,
    HTTPJSONToolAdapter, HTTPRoute,
)

identity = OIDCJWTIdentityProvider(
    issuer=os.environ["OIDC_ISSUER"],
    audience=os.environ["OIDC_AUDIENCE"],
    jwks_url=os.environ["OIDC_JWKS_URL"],
)
context = HTTPAuthorizationContextProvider(
    os.environ["PACA_CONTEXT_URL"],
    os.environ["PACA_CONTEXT_SERVICE_TOKEN"],
)
opa = OPAClient(os.environ["OPA_URL"], bearer_token=os.getenv("OPA_BEARER_TOKEN"))
store = SQLitePermitStore(os.environ["PACA_SQLITE_PATH"])
gateway = GuardedGateway(opa, store, identity, context)
tickets = HTTPJSONToolAdapter(
    os.environ["TICKET_API_BASE_URL"],
    {("ticket.create", "ticket-collection:default"): HTTPRoute("POST", "/v1/tickets")},
    bearer_token=os.environ["TICKET_API_TOKEN"],
)
result = gateway.authorize_and_execute(
    credential=access_token,  # obtain from the real caller; do not log it
    action="ticket.create",
    resource="ticket-collection:default",
    arguments={"title": "Example"},
    adapter=tickets,
    idempotency_key=stable_operation_id,
)
~~~

For the ticket example, the context tables must contain a tenant registration for `ticket-collection:default` and an active support principal with `can_create_tickets=true` and `suspended=false`. A file resource must be registered with an internal owner principal ID in the same tenant. These records are not seeded automatically. In production, grant the context service only `SELECT` on `paca_context_principals` and `paca_context_resources`; use a separately authenticated administrator process to change roles, capabilities, ownership, activation, or suspension. The OPA client requires a bearer token for non-loopback HTTPS OPA endpoints; loopback HTTP is permitted only for local development. The protected HTTP adapter also requires a configured bearer token. Do not expose OPA's unauthenticated admin/decision endpoint to untrusted networks.

## Guarantees and boundaries

- When all relevant effects go through **GuardedGateway** and a supplied adapter, a missing/invalid decision fails closed, the permit is bound to the canonical JSON request fingerprint, and the persistent claim prevents a second local execution claim for the same permit.
- The gateway cannot force third-party APIs to honor **Idempotency-Key**, cannot atomically commit a remote side effect and a local SQLite transaction, and cannot know whether a timed-out remote effect happened without downstream reconciliation.
- The sample filesystem adapter applies file effects, but its root directory, resource mapping, process privileges, mount configuration, and threat model still matter. Restrict OS permissions and run it with least privilege.
- SQLite is for single-host development/deployment. Use a transactional shared database with appropriate isolation/locking for multi-host replicas. The PostgreSQL adapter is included and CI integration-tested, but production deployments still need managed database provisioning, least-privilege roles, TLS/network restrictions, migrations, backups and operational monitoring.
- OIDC revocation and tenant-specific authorization still depend on the configured issuer and context service. JWT signature validation alone does not establish every application-specific authorization fact.
- The audit hash chain and stored head detect some tampering, including tail truncation if the head is not rewritten; they are not equivalent to an external WORM log, a signature, or a tamper-proof audit guarantee.
- The sample uses a manually versioned Rego policy marker (`paca-example-v4` in this branch). Version 4 binds ownership to internal principal IDs and tenant IDs instead of raw OIDC subjects. Production should validate and pin signed bundles, expose immutable bundle revisions, secure the OPA management plane, configure decision logs, and coordinate policy version changes with the protected effect boundary.
- This does not complete or validate the repository's original ALFA/UCON+ parser/compiler, establish formal correctness, certify compliance, demonstrate a novel research contribution, or constitute an independent security audit.

## Release checklist before real production use

1. Deploy an authenticated/TLS-protected OPA instance, verify policy bundles and pin a bundle revision.
2. Configure a real OIDC issuer/JWKS, claim mapping, token lifetime/revocation policy, and a trusted authorization-context service.
3. Use PostgresPermitStore for multi-host deployment with a managed PostgreSQL instance, a least-privilege runtime role, TLS/network restrictions, explicit schema migrations, backups and disaster recovery; reserve SQLite for single-host use. Apply all numbered migrations with the dedicated migration DSN using `python examples/apply_postgres_migration.py`, then run the gateway with `PACA_DATABASE_AUTO_MIGRATE=false`.
4. Require durable downstream idempotency or reconciliation for each remote effect; exercise timeout-after-commit and process-kill recovery tests against a non-production service.
5. Send audit events to an independently controlled log, restrict database and secret access, and define incident response.
6. Run the full CI suite, real OPA integration smoke, concurrency/fault-injection tests, adapter-specific adversarial tests, and a human security review against the deployment threat model.
