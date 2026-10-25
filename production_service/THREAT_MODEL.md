# Production-service threat model

## Scope

This document covers the production_service FastAPI authorization gateway, OPA/Rego policy decision point, JWT authentication, trusted context lookup, PostgreSQL operation state, and configured effect adapters. It is a design-level threat model, not evidence that a deployed system is secure.

## Assets

- Integrity of authorization decisions and policy revision.
- Caller identity, tenant membership, resource ownership, and current suspension state.
- Protected resources and downstream effects.
- Permit/execution idempotency records and recovery state.
- Audit events and secrets used to authenticate to identity, policy, database, and downstream services.

## Trust boundaries

1. **Caller to API:** all request fields are untrusted. The API must validate request shape, authenticate the bearer token, and never accept caller-selected callback code or destination URLs.
2. **API to identity provider:** trust only the configured issuer, audience, asymmetric signing algorithm, and HTTPS JWKS endpoint. Key rotation, revocation latency, and provider availability remain operational dependencies.
3. **API to context/database:** authorization attributes must come from trusted server-side state, not caller-supplied role/tenant/ownership claims. Tenant filters and least-privilege database roles are critical.
4. **API to OPA:** OPA availability, decision schema, and policy revision must be checked. Undefined, malformed, or unavailable decisions must fail closed. Protect the OPA endpoint from untrusted callers.
5. **Gateway to downstream effect:** the destination and operation must be fixed by server configuration. A local transaction cannot atomically commit an arbitrary remote API side effect.
6. **Audit database to independent storage:** an in-database hash chain or append-only trigger does not prevent a privileged database administrator from rewriting both events and integrity metadata.

## Threats and required controls

| Threat | Required control / residual risk |
|---|---|
| Forged, expired, wrong-audience, or wrong-issuer token | Verify signature and required claims against a fixed issuer/audience and trusted HTTPS JWKS. Test key rotation and revocation behavior for the deployment. |
| Caller forges roles, tenant, ownership, or suspension state | Resolve these attributes from trusted server-side context. Test cross-tenant access and missing/ambiguous context. |
| OPA outage, undefined result, or stale policy | Fail closed; pin and check expected policy revision; test policy rollover and failure paths. A deployment still needs a safe rollout procedure. |
| Replay or idempotency-key collision | Bind operation state to principal/tenant/request digest and enforce uniqueness in durable storage. Confirm the downstream service durably honors idempotency keys. |
| Concurrent execution or process crash | Use transactional claims and explicit unknown/reconciliation states. Exactly-once execution across PostgreSQL and an arbitrary remote API is not guaranteed. |
| SSRF or caller-controlled route | Use fixed server-configured destinations and routes, reject redirects, validate schemes/hosts, and apply egress network controls. |
| Path traversal or symlink race in file adapter | Confine access to a configured root, use no-follow path traversal, run with least privilege, and test on the target OS/filesystem. |
| Audit tampering or deletion | Restrict database permissions and export to independently controlled append-only/WORM storage with durable receiver-side deduplication. Local hashes alone are insufficient. |
| Secret leakage | Keep secrets out of source control and logs; use a secrets manager and rotate credentials. Example files contain placeholders only. |
| Denial of service | Apply ingress rate limits, request/body limits, timeouts, concurrency limits, monitoring, and recovery procedures at deployment. |

## Deployment gates before sensitive workloads

- Independent security review and threat-model review by the system owner.
- Real OIDC/JWKS configuration and documented key rotation/revocation behavior.
- Dedicated least-privilege database runtime and migration roles; TLS with certificate verification for remote PostgreSQL.
- OPA protected from public access; verified policy version and controlled rollout.
- Downstream-specific tests for duplicate requests, timeouts, crash-after-commit, retry, and reconciliation.
- TLS ingress, network segmentation/egress allow-list, secrets management, monitoring/alerting, backups and restore drills, audit retention, and incident response.
- Evidence that all required CI jobs pass on the exact candidate commit and a review of the final diff.

## Non-claims

This repository does not claim formal proof, exactly-once remote execution, tamper-proof audit against privileged administrators, complete ALFA/UCON+ compiler semantics, standards certification, or an independent security audit. CI results apply only to the exact commit and tests that ran.
