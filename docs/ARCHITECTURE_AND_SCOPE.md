# PACA++ architecture and scope contract

This document is the repository-level source of truth for product positioning and implementation boundaries. Package-specific READMEs and threat models add detail; they must not be read as merging separate implementations.

## 1. Primary purpose

PACA++ investigates and implements **policy-aware authorization at the protected-action boundary**. The goal is to bind an authorization decision to the exact authenticated principal, tenant, action, resource, arguments, trusted context and policy revision that are in force when an effect is attempted.

The central enforcement sequence is:

1. Authenticate the caller using a configured trusted identity provider.
2. Obtain authorization facts from a trusted server-side source.
3. Evaluate the request against a policy decision point.
4. Issue a short-lived permit bound to the request and decision.
5. At execution, verify the permit, request fingerprint, current context and current policy revision.
6. Atomically claim local execution/idempotency state before invoking the configured adapter.
7. Persist the outcome or mark it unknown when the remote outcome cannot safely be determined.
8. Record audit information and export it to independently controlled storage where required.

This is an authorization architecture. It is not itself an identity provider or a replacement for an organization's complete IAM lifecycle.

## 2. Three distinct areas — correct claims

### Enterprise authorization architecture — primary category

PACA++ is designed to centralize policy decisions and guard protected effects across services and agent tools. The production service demonstrates one concrete gateway implementation. This is the most accurate overall description.

### Database security — implemented capability, not a complete database security product

The production service applies PostgreSQL RLS to its tenant-bearing tables. Its database verifier validates a short-lived HMAC context bound to tenant, verified principal, backend PID and transaction ID. This prevents a party holding only the restricted runtime database credential from forging a different tenant context under the tested conditions.

The boundary does not protect against compromise of the API process/signing key, database owner/superuser, host, or database server. It is tenant-level isolation, not a replacement for OPA's principal/resource authorization. The separate prototype PostgreSQL store does not provide the same tenant-RLS guarantee.

### Enterprise access management — integration/application area

The production service validates tokens from one configured OIDC issuer/audience and uses trusted claims and resource facts for authorization. This supports an access-management use case, but does not implement a complete IAM suite. User lifecycle, provisioning/deprovisioning, directory administration, MFA/SSO user experience, access certification and enterprise-wide entitlement governance remain external responsibilities.

## 3. Implementation boundaries

| Component | Owns | Does not imply |
|---|---|---|
| `production_service/` | FastAPI gateway, JWT validation, OPA decisions, PostgreSQL permits/executions, signed tenant context/RLS, configured adapters | Features from the prototype, complete IAM, arbitrary agent-framework integration |
| `prototype/` | Research prototype, legacy in-memory example, separate OPA/OIDC hardening path, agent boundaries/reference runtime and prototype stores | Same schema, same identity model or same RLS guarantees as production_service |
| `compiler/` | Experimental parser/emitter for an explicitly limited policy subset | Complete ALFA/UCON+ support or semantic equivalence between ASP and Cedar |
| `legacy_policy_engine/` | Preserved historical implementation | Supported production API or root-CI coverage unless explicitly wired into CI |
| `agent/` | Mock/placeholder area | Real framework integration or proof that a host cannot bypass the guarded runtime |

A test result belongs to the component and exact commit that ran it. Never transfer a passing result from one component to another.

## 4. Effect semantics and distributed-systems limit

A local database transaction cannot atomically commit an arbitrary remote HTTP/API effect. PACA++ can create durable local permits, atomically claim local execution state, pass a stable execution idempotency key downstream, and record an uncertain outcome. It cannot guarantee exactly-once remote execution unless the downstream system supplies a compatible durable idempotency and reconciliation contract.

For ambiguous timeouts, connection loss or process crashes, the safe state may be `unknown`. Do not automatically retry an effect whose completion is uncertain. Reconcile with the downstream system before deciding whether a retry is safe.

## 5. AI-agent security boundary

The prototype reference runtime and boundary modules can constrain configured retrieval, tool invocation, inter-agent messages and output release. They do not understand every prompt injection, guarantee that all host paths are guarded, or make untrusted retrieved/tool content safe. A real deployment must integrate its actual model and tool adapters, authenticate the host/agent identity, bind tools and resources server-side, and ensure there is no alternate path to protected effects.

The production-service gateway is an authorization/effect service; it is not by itself a full autonomous-agent runtime.

## 6. Evidence standard

Claims must be labelled by evidence type:

- **Implemented:** code exists in the named component.
- **Unit/integration tested:** specified automated tests passed on a named commit.
- **Evaluated:** reproducible measurements against declared baselines and workloads exist.
- **Independently assessed:** an external reviewer or auditor has examined the system and scope.
- **Production deployed:** a real deployment has completed operational and security acceptance.

CI success alone does not establish comparative effectiveness, research novelty, production readiness, standards compliance or universal security.

## 7. Required deployment gates

Before sensitive workloads: deployment-specific threat model and independent review; real OIDC/JWKS configuration and claim governance; separate secrets and database roles; backup/restore and migration rehearsal; private OPA with controlled policy rollout; TLS ingress and database verification; network/egress controls; rate/concurrency limits; monitoring and incident response; audit export to independently controlled storage; and downstream idempotency/reconciliation tests.

## 8. Research evaluation required to substantiate effectiveness

Compare at least: (a) agent/application without PACA++; (b) a clearly specified conventional authorization baseline; and (c) PACA++ under the same agent, tools, policies and workloads. Report attack success rate, legitimate-task success/utility, false-denial rate, authorization bypasses, latency overhead, throughput, recovery correctness and resource consumption. Publish scenarios, seeds, configurations, raw results and analysis. Do not claim superiority until the comparison is completed and independently reproducible.
