# Production-service threat model

## Scope and identity convention

This document covers the separate `production_service/` FastAPI gateway, its Rego policy, OIDC/JWKS validation, PostgreSQL state, and configured execution adapters. It is a design threat model, not evidence that a deployment is secure.

The gateway verifies RS256 tokens for one configured issuer/audience. In this implementation, `principal.id` is the verified token `sub`; `protected_resources.owner_id` must be provisioned to match that subject for the configured issuer. The `roles`, `scopes`, and `tools` attributes are derived from signed token claims. Only use those claims when the configured issuer is trusted to set them correctly. This service does not implement the separate prototype's internal-principal mapping context service.

## Assets

- Integrity of authorization decisions and expected policy revision.
- Caller identity, tenant, scopes/roles/tools and resource ownership.
- Protected resources and downstream effects.
- Permit/execution/idempotency state and recovery classification.
- Audit events and credentials used with identity, OPA, database and downstream services.

## Trust boundaries

1. **Caller → API:** request data is untrusted. Validate request shape, authenticate the token, and never accept caller-selected callbacks or destination URLs.
2. **API → OIDC provider:** trust only the configured issuer, audience, RS256 signing algorithm and HTTPS JWKS endpoint. Key rotation, revocation latency and provider availability remain deployment dependencies.
3. **API → PostgreSQL:** trusted resource facts must be provisioned by an administrative process. The API signs tenant context with a separate HMAC key; database RLS verifies it against a private key table and binds it to the current backend/transaction. Use a restricted runtime role, TLS peer verification for remote databases, and separate migration/admin credentials.
4. **API → OPA:** require a well-formed decision and the expected policy revision on both allow and deny results. OPA failure/undefined result fails closed. Keep OPA private and coordinate policy rollout with the gateway.
5. **Gateway → downstream effects:** destination/action are fixed by server configuration; the API cannot force a downstream service to implement idempotency.
6. **Audit DB → independent storage:** an append-only trigger is defense-in-depth, not tamper-proof storage against an owner or superuser.

## Threats and controls

| Threat | Control and residual risk |
|---|---|
| Forged, expired, wrong-issuer/audience token | Verify signature and claims against one configured issuer/audience and HTTPS JWKS. Test rotation/revocation for the real deployment. |
| Forged tenant, roles/scopes, ownership | Only trust claims set by the configured issuer; provision resource owners under the stated subject convention; bind the verified tenant/principal to a short-lived database HMAC context and enforce tenant RLS. OPA still makes the principal/resource decision. |
| OPA outage, malformed result, stale policy | Fail closed; require and compare revision; test real OPA allow/deny/readiness and rollout behavior. |
| Permit replay/idempotency collision | Bind durable execution state to principal/tenant/request digest; enforce uniqueness and test concurrent claims. Downstream idempotency still must be independently verified. |
| Process crash or uncertain remote outcome | Record an explicit unknown outcome and do not blindly retry. Exercise downstream-specific crash-after-commit and reconciliation paths. |
| SSRF/caller-controlled route | Fixed server-configured base URL/routes, reject redirects, require HTTPS for remote upstreams, and enforce egress allow-lists. |
| Path traversal/symlink attack | Keep logical-resource mapping server controlled; use confined no-follow operations and run tests on the deployment OS/filesystem. |
| Audit alteration/deletion | Runtime role has no audit update/delete privilege; export to independently controlled append-only/retention-protected storage. A database administrator can still alter local history. |
| Ambiguous headers/framing or oversized payloads | Reject duplicate security/framing headers and Content-Length plus Transfer-Encoding; cap request bodies while receiving them and stream/cap downstream response reads. Still configure ingress, concurrency and rate limits. |
| Secret leakage/DoS | Secrets manager and rotation; ingress/request/concurrency/rate limits, timeouts, observability, backups, restore drills, and incident response. |

## Current safeguards checked into this repository

- The local Compose API connects through `paca_runtime`, not the bootstrap/admin credential.
- Runtime grants permit reading trusted resources, narrowly scoped permit/execution writes, and audit select/insert only. Row-level-security policies scope all four tenant-bearing tables through `paca_current_tenant_id()`, which validates an HMAC-SHA-256 context bound to tenant, verified principal, backend PID, transaction ID, and a short expiry. The HMAC key is held in an administrator-owned private schema inaccessible to the runtime role. Execution rows are composite-FK-bound to their permit's tenant and principal.
- Tenant-aware store methods set the RLS context in a transaction and finalization requires both tenant and principal. Global stale-execution recovery is exposed only through a fixed, bounded, audited `SECURITY DEFINER` function; the runtime role cannot issue the original unscoped sweep as direct table DML.
- Rego decisions carry the policy revision on default-deny and allow paths; CI exercises the actual OPA client readiness and an allow/deny pair.
- Configuration rejects plaintext HTTP to remote OPA/downstream endpoints and requires `sslmode=verify-full` for remote PostgreSQL URLs.
- PostgreSQL tests use a separate admin DSN for fixture provisioning and run service operations through the restricted runtime DSN.

These are code-level checks, not independent deployment audit results. Existing database volumes do not rerun initialization scripts automatically; role migration and grants must be applied explicitly after a verified backup.

## Runtime-credential compromise test and residual risk

The PostgreSQL integration suite now checks that the runtime role cannot read the private HMAC key table, cannot forge a different tenant context by changing custom GUCs, and cannot replay a captured signed context in a new transaction. The signed context includes the tenant, verified principal, backend PID, transaction ID, issue/expiry times, and key ID. These tests are designed to distinguish the database credential from the separately protected application signing key.

A successful result demonstrates the tested RLS boundary against a party holding only the restricted runtime database credential and attempting ordinary SQL under that role. It does **not** protect against compromise of the API process or its HMAC key, the database owner/superuser, the host, or an exploitable PostgreSQL server.

One deliberate cross-tenant exception remains: `paca_mark_stale_executions_unknown` is a bounded, audited `SECURITY DEFINER` function executable by `paca_runtime` for startup recovery. A stolen runtime credential can invoke that function and change the state of stale executions across tenants (for example, classify them as `unknown`). This is a constrained availability/state-transition capability, not arbitrary cross-tenant row access, but it remains a cross-tenant authority. Move global recovery to a separately authenticated worker/role if that residual capability is unacceptable.

The runtime role also has write access to permit and execution state within the signed tenant context. The HMAC key must be protected separately from the runtime database credential, and API/database clocks must remain synchronized because context expiry is time-checked.

## RLS limitation

PostgreSQL custom GUCs remain mutable by a session, so the RLS policies validate the signed context instead of trusting a tenant setting alone. The runtime role can alter GUC values but cannot forge the HMAC, read the private key table, or replay a captured signature in another backend or transaction. The API key and database key copy must be protected independently of the runtime database credential. This boundary is tenant-level: it does not replace principal/resource checks in OPA and application queries, and the explicit stale-execution recovery function remains the cross-tenant exception described above.

## Deployment gates before sensitive workloads

- Independent security/threat-model review.
- Real OIDC/JWKS configuration with documented rotation/revocation behavior.
- Restricted runtime and migration roles, remote PostgreSQL TLS verification, and tested backups/restores.
- OPA inaccessible to untrusted callers, a verified policy revision and controlled rollout procedure.
- Downstream-specific tests for duplicate requests, timeouts, crash-after-commit, retry and reconciliation.
- TLS ingress, network segmentation/egress controls, secrets management, monitoring/alerts, audit retention and incident response.

## Non-claims

This repository does not claim formal proof, exactly-once remote execution, tamper-proof auditing against privileged administrators, complete ALFA/UCON+ compiler semantics, standards certification, an independent security audit, production approval or research novelty. CI evidence applies only to the exact revision and tested scenarios.
