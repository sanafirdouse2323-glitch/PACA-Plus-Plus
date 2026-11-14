# PACA++ — policy-aware authorization and controlled action

PACA++ is an **enterprise authorization research and engineering project**. Its central question is whether an authorization decision remains bound to the authenticated principal, tenant, action, resource, policy revision and trusted context when a protected effect is attempted.

Its primary scope is **authorization enforcement at the protected-action boundary**, including controlled execution for AI-agent tools. It is not a complete identity and access management (IAM) suite, a general-purpose database security product, or a universal prompt-injection detector.

> **Repository lineage:** This is the earlier service/compiler-oriented PACA++ codebase. The separate [PACA-Plus-Plus-New repository](https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus-New) is the successor project for the provenance-anchored continuous-authorization research line focused on autonomous systems and LLM agents. The two repositories have different implementations, tests and evidence. Do not attribute this repository's FastAPI/PostgreSQL features to the newer repository, or transfer the newer repository's agent mechanisms and benchmark results to this one. In this codebase, AI-agent integration remains a limited reference/integration area rather than a complete production agent-security product.

## Positioning and target applications

PACA++ is primarily an **authorization-enforcement architecture**. The current repository combines a FastAPI/OPA/PostgreSQL gateway with a separate research prototype. The following are target uses and potential customer groups, not existing customers, validated demand or compliance claims.

| Application area | Potential users and need | What this repository provides—and its limit |
|---|---|---|
| **Enterprise authorization across applications** | Large enterprises, SaaS providers, IT departments and security teams that need consistent, reviewable access decisions across services | The production service implements one configurable OIDC/JWT-to-OPA authorization gateway with permit and protected-execution checks. It is not a complete IAM suite: identity lifecycle, provisioning, directory administration, access certification and a complete SSO/MFA product remain external. |
| **PostgreSQL tenant isolation** | Cloud platforms, healthcare software, fintech and multi-tenant SaaS providers that need to prevent cross-tenant data access | The production service implements PostgreSQL row-level security (RLS) with a short-lived HMAC-signed tenant context verified inside PostgreSQL. This protects the documented tenant-scoped service tables under the stated trust assumptions; it is not a general-purpose database-security product and does not establish regulatory compliance. |
| **Authorization at AI-agent action boundaries** | Organizations deploying autonomous agents and distributed applications that need policy checks before protected tool or service actions | The prototype contains guarded agent boundaries and a synchronous reference runtime. Separately, `agent/paca_client.py` is a thin host-side client for the production-service API. Neither is a complete agent platform or a vendor-specific framework adapter; deployments still need real host integration, no-bypass controls and independent evaluation. |

These areas are related but distinct: enterprise authorization is the primary architecture, PostgreSQL RLS is one implemented isolation capability, and AI-agent authorization is an application area. The named sectors are prospective users, not evidence of customer adoption or sector-specific certification.

## Repository architecture — keep the implementations distinct

| Path | Role | Evidence and limits |
|---|---|---|
| `production_service/` | Separate FastAPI authorization gateway using verified JWTs, OPA, PostgreSQL permits/executions, RLS and configured effect adapters | Main controlled-evaluation service. See its README and threat model. |
| `prototype/` | Python research prototype: legacy in-memory engine plus a separate OPA/OIDC hardening path, agent boundaries/runtime, SQLite and PostgreSQL stores | Useful for experiments. Its stores and identity/context model are not interchangeable with the production service. |
| `compiler/` and root `tests/` | Experimental parser/emitter for a limited policy subset | Not a complete or standards-compatible ALFA/UCON+ compiler. Tests do not prove ASP/Cedar semantic equivalence. |
| `legacy_policy_engine/` | Older policy parser, compiler/evaluator and engine package | Separate historical implementation; not part of the production-service API and not covered by the current root CI workflow. |\n| `archive/paca-plus-plus-new/` | Text-only snapshot and recovery notes for the separate newer repository | Read-only archival material; several source entries are embedded in text filenames and are not an importable or runnable copy. Use the linked standalone repository for its current code. |
| `agent/` | Thin standard-library HTTP client for the production service's authorize/execute API, with tests and a small placeholder file | Not an LLM agent, not a LangChain/LangGraph/AutoGen adapter, and not proof that every host action is routed through the gateway. |

Do not infer that a feature in one path is automatically present in another. In particular, the prototype PostgreSQL store is not the production service's tenant-RLS boundary.

## Production-service quick start

Follow [production_service/README.md](production_service/README.md) from its own directory. Use a fresh local evaluation environment, generate independent secrets, configure a real test OIDC issuer/JWKS endpoint, provision trusted resource facts, and verify both `/healthz` and `/readyz`.

The checked-in example identity-provider values and HMAC key are placeholders. Replace them before use. Existing database volumes require the documented, backup-first upgrade procedure; restarting containers alone does not apply migrations or grants.

## Tests and what they prove

CI runs separate production-service, prototype/hardening and compiler workflows. A passing workflow proves only that the workflow's declared tests passed on the exact commit and environment.

The production-service tests cover selected authentication/OPA flows, permit and execution behavior, PostgreSQL tenant RLS, signed-context forgery/replay attempts, privilege boundaries and adapter safety. They do **not** prove resistance to every attack, atomicity with arbitrary remote effects, or safe operation in an unreviewed deployment.

The prototype's deterministic scenarios are a small hand-authored test set, not an external benchmark. Compiler regression tests cover the implemented subset and generated-text invariants, not language conformance or semantic equivalence.

## Deployment gates — before sensitive enterprise workloads

1. Complete a deployment-specific threat model and independent security review.
2. Configure the real identity provider, issuer/audience/JWKS, trusted claim mapping and key-rotation/revocation process.
3. Protect the API HMAC key independently from the database runtime credential; use separate migration/admin and runtime roles.
4. Apply database upgrades only after a verified backup; test restore and key rotation.
5. Keep OPA private and coordinate policy revision rollout with protected effects.
6. Configure TLS ingress, network segmentation, egress allow-lists, rate/concurrency limits, secrets management, monitoring and incident response.
7. Verify downstream idempotency and reconciliation for each external effect, including timeout and crash-after-commit cases.
8. Integrate a real agent framework and test that every tool/effect path passes through the guard.
9. Benchmark against relevant baselines using attack success, legitimate-task utility, false denials, latency and recovery metrics.

## Research and product claims

PACA++ is a research/engineering foundation with meaningful implemented controls. It is **not production-certified**, independently audited, formally verified, or proven superior to OPA, Cedar, commercial IAM products, or other agent-security systems. Do not claim complete IAM, universal prompt-injection prevention, exactly-once remote execution, tamper-proof audit against administrators, full ALFA/UCON+ support, or demonstrated benchmark superiority without new evidence.

See [the architecture and scope contract](docs/ARCHITECTURE_AND_SCOPE.md), [production-service threat model](production_service/THREAT_MODEL.md), and [prototype hardening guide](prototype/docs/SECURITY_HARDENING.md). The file [prototype/THREAT_MODEL.md](prototype/THREAT_MODEL.md) applies only to the legacy in-memory engine; agent-boundary coverage and gaps are in [prototype/docs/THREAT_COVERAGE.md](prototype/docs/THREAT_COVERAGE.md).
