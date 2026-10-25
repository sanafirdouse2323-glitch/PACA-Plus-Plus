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
3. **API → PostgreSQL:** trusted resource facts must be provisioned by an administrative process. Use a restricted runtime role, tenant-scoped queries/RLS where configured, TLS peer verification for remote databases, and separate migration/admin credentials.
4. **API → OPA:** require a well-formed decision and the expected policy revision on both allow and deny results. OPA failure/undefined result fails closed. Keep OPA private and coordinate policy rollout with the gateway.
5. **Gateway → downstream effects:** destination/action are fixed by server configuration; the API cannot force a downstream service to implement idempotency.
6. **Audit DB → independent storage:** an append-only trigger is defense-in-depth, not tamper-proof storage against an owner or superuser.

## Threats and controls

| Threat | Control and residual risk |
|---|---|
| Forged, expired, wrong-issuer/audience token | Verify signature and claims against one configured issuer/audience and HTTPS JWKS. Test rotation/revocation for the real deployment. |
| Forged tenant, roles/scopes, ownership | Only trust claims set by the configured issuer; provision resource owners under the stated subject convention; enforce tenant equality in the policy and queries. |
| OPA outage, malformed result, stale policy | Fail closed; require and compare revision; test real OPA allow/deny/readiness and rollout behavior. |
| Permit replay/idempotency collision | Bind durable execution state to principal/tenant/request digest; enforce uniqueness and test concurrent claims. Downstream idempotency still must be independently verified. |
| Process crash or uncertain remote outcome | Record an explicit unknown outcome and do not blindly retry. Exercise downstream-specific crash-after-commit and reconciliation paths. |
| SSRF/caller-controlled route | Fixed server-configured base URL/routes, reject redirects, require HTTPS for remote upstreams, and enforce egress allow-lists. |
| Path traversal/symlink attack | Keep logical-resource mapping server controlled; use confined no-follow operations and run tests on the deployment OS/filesystem. |
| Audit alteration/deletion | Runtime role has no audit update/delete privilege; export to independently controlled append-only/retention-protected storage. A database administrator can still alter local history. |
| Secret leakage/DoS | Secrets manager and rotation; ingress/request/concurrency/rate limits, timeouts, observability, backups, restore drills, and incident response. |

## Current safeguards checked into this repository

- The local Compose API connects through `paca_runtime`, not the bootstrap/admin credential.
- Runtime grants permit reading trusted resources, narrowly scoped permit/execution writes, and audit select/insert only.
- Rego decisions carry the policy revision on default-deny and allow paths; CI exercises the actual OPA client readiness and an allow/deny pair.
- Configuration rejects plaintext HTTP to remote OPA/downstream endpoints and requires `sslmode=verify-full` for remote PostgreSQL URLs.
- PostgreSQL tests use a separate admin DSN for fixture provisioning and run service operations through the restricted runtime DSN.

These are code-level checks, not independent deployment audit results. Existing database volumes do not rerun initialization scripts automatically; role migration and grants must be applied explicitly after a verified backup.

## Deployment gates before sensitive workloads

- Independent security/threat-model review.
- Real OIDC/JWKS configuration with documented rotation/revocation behavior.
- Restricted runtime and migration roles, remote PostgreSQL TLS verification, and tested backups/restores.
- OPA inaccessible to untrusted callers, a verified policy revision and controlled rollout procedure.
- Downstream-specific tests for duplicate requests, timeouts, crash-after-commit, retry and reconciliation.
- TLS ingress, network segmentation/egress controls, secrets management, monitoring/alerts, audit retention and incident response.

## Non-claims

This repository does not claim formal proof, exactly-once remote execution, tamper-proof auditing against privileged administrators, complete ALFA/UCON+ compiler semantics, standards certification, an independent security audit, production approval or research novelty. CI evidence applies only to the exact revision and tested scenarios.
