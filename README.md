# PACA++ — policy-aware authorization and controlled action

PACA++ is an **enterprise authorization research and engineering project**. Its central question is whether an authorization decision remains bound to the authenticated principal, tenant, action, resource, policy revision and trusted context when a protected effect is attempted.

Its primary scope is **authorization enforcement at the protected-action boundary**, including controlled execution for AI-agent tools. It is not a complete identity and access management (IAM) suite, a general-purpose database security product, or a universal prompt-injection detector.

> **Repository lineage:** This is the earlier service/compiler-oriented PACA++ codebase. The separate [PACA-Plus-Plus-New repository](https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus-New) is the successor project for the provenance-anchored continuous-authorization research line focused on autonomous systems and LLM agents. The two repositories have different implementations, tests and evidence. Do not attribute this repository's FastAPI/PostgreSQL features to the newer repository, or transfer the newer repository's agent mechanisms and benchmark results to this one. In this codebase, AI-agent integration remains a limited reference/integration area rather than a complete production agent-security product.

## Accurate project positioning

- **Primary category — enterprise authorization architecture:** authenticate a caller, obtain trusted resource context, evaluate policy, issue a short-lived permit, re-check authorization at execution, and record the outcome.
- **Important security capability — tenant isolation:** the production-service PostgreSQL implementation uses row-level security (RLS) backed by a short-lived HMAC-signed context verified inside PostgreSQL. This is tenant-level isolation; OPA and application checks still make principal/resource decisions.
- **Application area — AI-agent authorization:** the prototype provides reference boundaries and a model-vendor-neutral guarded runtime. A host must integrate its actual model and tool adapters and must not expose bypass paths.
- **Not a complete IAM replacement:** the repository does not provide a full identity lifecycle, user provisioning/deprovisioning, enterprise directory administration, access certification, or a complete SSO/MFA product.

## Market applications and customer needs

The following are **target application areas and potential customer groups**, not claims of signed customers, validated demand, regulatory certification or complete product coverage.

| Application area | Potential customers | Core need | PACA++ relevance and current boundary |
|---|---|---|---|
| **Enterprise access management and cross-application authorization** | Large enterprises, SaaS providers, IT departments and security teams | Apply consistent, reviewable access decisions across applications and services | PACA++ is aimed at the authorization-enforcement layer: applications can delegate policy decisions and protected-action checks to a shared authorization service. It is **not** a complete IAM platform: identity lifecycle, directory administration, provisioning, access certification and a full SSO/MFA suite are outside the repository's current scope. |
| **Database security and multi-tenant isolation** | Cloud platforms, healthcare software providers, financial-technology services and multi-tenant SaaS providers | Prevent one tenant or customer from reading or changing another tenant's data | The production-service implementation includes a concrete PostgreSQL tenant-isolation design using row-level security (RLS) and a short-lived HMAC-signed tenant context verified inside PostgreSQL. This is a specific PostgreSQL capability, not a universal database-security product, and it does not by itself establish healthcare, financial-sector or other regulatory compliance. |
| **Enterprise authorization for AI agents and distributed applications** | Organizations deploying autonomous AI agents and complex distributed applications | Ensure authorization and information-use restrictions are checked when an agent attempts a protected tool or service action | PACA++ focuses on binding authorization to the principal, tenant, action, resource, policy revision and trusted context at the protected-action boundary. This is an architectural direction and guarded integration foundation; real agent-framework/tool adapters, complete host-path coverage and independent attack-resistance evidence remain deployment and evaluation work. |

These areas overlap but are not interchangeable: enterprise access management is the broader application context, PostgreSQL RLS is one implemented tenant-isolation capability, and AI-agent security is a protected-action use case. The potential-customer descriptions are positioning hypotheses; customer interviews, pilots and measured deployment results are needed to validate market demand.

## Repository architecture — keep the implementations distinct

| Path | Role | Evidence and limits |
|---|---|---|
| `production_service/` | Separate FastAPI authorization gateway using verified JWTs, OPA, PostgreSQL permits/executions, RLS and configured effect adapters | Main controlled-evaluation service. See its README and threat model. |
| `prototype/` | Python research prototype: legacy in-memory engine plus a separate OPA/OIDC hardening path, agent boundaries/runtime, SQLite and PostgreSQL stores | Useful for experiments. Its stores and identity/context model are not interchangeable with the production service. |
| `compiler/` and root `tests/` | Experimental parser/emitter for a limited policy subset | Not a complete or standards-compatible ALFA/UCON+ compiler. Tests do not prove ASP/Cedar semantic equivalence. |
| `legacy_policy_engine/` | Preserved legacy source snapshot | Separate compatibility material; not part of the production-service API and not covered by the root CI contract unless a workflow explicitly says so. |
| `agent/` | Placeholder/mock-agent area | Not a supported real-agent framework integration. Use the prototype reference runtime as a starting point and integrate a real host explicitly. |

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

See [the architecture and scope contract](docs/ARCHITECTURE_AND_SCOPE.md), [production-service threat model](production_service/THREAT_MODEL.md), and [prototype threat model](prototype/THREAT_MODEL.md) before making deployment or research claims.
