# PACA++ hardening layer: architecture, configuration, and claims

## What this branch adds

The legacy **AuthorizationEngine** remains an in-memory, single-process research MVP. This branch adds a separate integration path intended to close several concrete gaps without silently rewriting the original ALFA/UCON+ compiler work:

- **Policy decision point:** **OPAClient** calls a named Open Policy Agent (OPA) Data API decision. An absent/malformed decision, missing permit version, timeout, HTTP error, or transport failure raises an error; the gateway does not treat that as permission.
- **Policy version recheck:** an allowed decision carries a version. The gateway asks OPA for the active version immediately before the effect and rejects a mismatch. This narrows, but cannot atomically eliminate, the race with policy reload; coordinate policy deployments with effect commits where that matters.
- **Authentication:** **OIDCJWTIdentityProvider** verifies RS256 JWT signatures using a configured HTTPS JWKS endpoint and validates issuer, audience, expiry, and required claims. It never accepts merely decoded tokens. It is an adapter, not an identity provider or credential issuer.
- **Trusted context:** **HTTPAuthorizationContextProvider** obtains contextual attributes from an administrator-configured HTTPS service using a separate service credential. Request-supplied roles/attributes must not be substituted for the result. The gateway rejects a context response that tries to overwrite verified identity.
- **Enforcement adapters:** **FilesystemToolAdapter** maps administrator-defined logical resource IDs to a fixed local root and uses POSIX descriptor-relative, no-follow traversal. **HTTPJSONToolAdapter** can call only administrator-configured action/resource routes over HTTPS, blocks redirects, and sends a downstream idempotency key.
- **Coordinated durable state:** **SQLitePermitStore** persists short-lived permits, state versions, execution claims, idempotency keys, results, and audit events in a file-backed SQLite database. SQLite transactions serialize local processes sharing that file on the same machine; this is not a distributed database for multi-host coordination.
- **Failure and replay behavior:** the store claims an operation durably before invoking an adapter. If a process crashes or an adapter raises after a possible partial side effect, the operation becomes/should be reconciled as **unknown**; the system does not automatically replay it. A downstream service that durably honors the idempotency key or exposes reconciliation is required to safely resume.
- **Audit integrity checking:** events are persisted with a hash-linked chain and **verify_audit_chain()** checks the chain. This detects edits that do not also rewrite subsequent hashes, but it is **not tamper-proof** against an attacker who can rewrite the database and recompute the hashes. Production audit should also be streamed to an independently controlled append-only system.
- **Adversarial checks:** the new test file covers OPA failures, malformed decisions, stale policy/state, expired permits, repeated idempotency keys, effect failures, crash recovery, concurrent execution, symlink traversal, fixed API routes, and audit-chain tampering.

## Run locally

Requires Python 3.10+ and Docker for the real OPA smoke test.

~~~bash
cd prototype
python -m pip install -e .
python -m unittest discover -s tests -v
python examples/demo.py
python experiments/run_experiments.py
docker compose up -d opa
python examples/opa_smoke.py
docker compose down
~~~

The OPA Compose port is bound to loopback. The example Rego policy permits an analyst to read only a resource owned by the verified subject, permits ticket creation only when a trusted context grants the support role and explicit capability, and denies suspended subjects or requests missing the explicit non-suspended claim. It is an illustrative policy, not a universal production policy. Increment **policy_version** whenever authorization semantics change; production bundle deployments should tie this to an immutable, verified bundle revision and coordinate rollout.

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

For the ticket example, the trusted context service must return an authorization role of support and can_create_tickets=true for an authorized caller; those values must be derived server-side, not from tool arguments. The configured context service and policy must return the fields the Rego policy expects. The route/resource map, OIDC issuer/audience/JWKS URI, database path, OPA endpoint, and service credentials are trusted deployment configuration. Do not expose OPA's unauthenticated admin/decision endpoint to untrusted networks.

## Guarantees and boundaries

- When all relevant effects go through **GuardedGateway** and a supplied adapter, a missing/invalid decision fails closed, the permit is bound to the canonical JSON request fingerprint, and the persistent claim prevents a second local execution claim for the same permit.
- The gateway cannot force third-party APIs to honor **Idempotency-Key**, cannot atomically commit a remote side effect and a local SQLite transaction, and cannot know whether a timed-out remote effect happened without downstream reconciliation.
- The sample filesystem adapter applies file effects, but its root directory, resource mapping, process privileges, mount configuration, and threat model still matter. Restrict OS permissions and run it with least privilege.
- SQLite is for single-host development/deployment. Use a transactional shared database with appropriate isolation/locking for multi-host replicas. A PostgreSQL implementation is not included in this branch.
- OIDC revocation and tenant-specific authorization still depend on the configured issuer and context service. JWT signature validation alone does not establish every application-specific authorization fact.
- The audit hash chain is not equivalent to an external WORM log, a signature, or a tamper-proof audit guarantee.
- The sample uses a manually versioned Rego policy marker. Production should validate and pin signed bundles, expose immutable bundle revisions, secure the OPA management plane, configure decision logs, and coordinate policy version changes with the protected effect boundary.
- This does not complete or validate the repository's original ALFA/UCON+ parser/compiler, establish formal correctness, certify compliance, demonstrate a novel research contribution, or constitute an independent security audit.

## Release checklist before real production use

1. Deploy an authenticated/TLS-protected OPA instance, verify policy bundles and pin a bundle revision.
2. Configure a real OIDC issuer/JWKS, claim mapping, token lifetime/revocation policy, and a trusted authorization-context service.
3. Decide on a supported coordination database for the deployment topology and define retention, encryption, backups, migration, and disaster recovery.
4. Require durable downstream idempotency or reconciliation for each remote effect; exercise timeout-after-commit and process-kill recovery tests against a non-production service.
5. Send audit events to an independently controlled log, restrict database and secret access, and define incident response.
6. Run the full CI suite, real OPA integration smoke, concurrency/fault-injection tests, adapter-specific adversarial tests, and a human security review against the deployment threat model.
