# PACA++ security baseline and effectiveness roadmap

**Scope:** this document covers this repository only: the FastAPI production-service gateway, PostgreSQL tenant-isolation implementation, Python research prototype and its guarded agent runtime, the limited compiler experiment, and the host-side client in `agent/`. It does not describe or import the separate `PACA-Plus-Plus-New` implementation.

**Review date:** 14 November 2026.

This is a threat-informed engineering baseline, not a certification, compliance assessment, independent penetration test or proof of effectiveness. The frameworks below are used as design and verification references; PACA++ does not claim conformance to every requirement in them.

## 1. Current reference baseline

| Reference | Relevant guidance | How PACA++ uses it |
|---|---|---|
| [NIST SP 800-207 — Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final) | Do not infer trust from network location; make access decisions about subjects and protected resources. | Treat the API as a policy enforcement point; authenticate the caller and resolve trusted resource context before each protected action. |
| [IETF RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html) | Restrict token privileges and audiences; consider sender-constrained tokens such as DPoP or mutual TLS to reduce bearer-token replay. | Pin issuer, audience and RS256; use HTTPS JWKS and a configured access-token-only claim. DPoP/mTLS sender-constrained access tokens are not implemented in this repository. |
| [IETF RFC 8725 — JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html) | Pin acceptable algorithms, validate issuer and audience, do not trust token-supplied key URLs, and use mutually exclusive validation rules for different JWT kinds. | Use a fixed configured JWKS endpoint, RS256-only verification, issuer/audience checks, required claims and the configured `token_use=access` marker. This repository does not claim full RFC 9068 JWT Access Token Profile conformance. |
| [IETF RFC 9449 — DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) | Bind OAuth tokens to proof of possession to reduce replay of stolen tokens. | Recorded as a high-priority deployment/integration gap. Current API authentication uses bearer tokens. |
| [OWASP API Security Top 10:2023](https://owasp.org/API-Security/) | Broken object/function authorization, authentication failures, unrestricted resource consumption, SSRF, misconfiguration and unsafe upstream API consumption. | Test tenant/resource ownership and action/scope rules; constrain routes and input sizes; require network controls and deployment-level rate limits. |
| [OWASP ASVS 5.0.0](https://asvs.owasp.org/) | A verification requirement catalogue for web applications and services. | Use as a test-planning and review checklist. No ASVS level or compliance claim is made. |
| [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) and [Securing Agentic Applications V2](https://genai.owasp.org/resource/securing-agentic-applications-v2/) | Threats and mitigations spanning agent identity, tool misuse, runtime protection, supply chain and assurance testing. V2 was published 10 November 2026. | Map guarded tool calls, trusted tool/resource configuration, provenance, output boundaries, least privilege and end-to-end host integration to these concerns. |
| [OWASP Agent Control Standard (ACS)](https://genai.owasp.org/resource/agent-control-standard-acs/) | Emerging guidance for inspectable, traceable and runtime-controllable agents and policy hooks. | A future interoperability target for framework hooks; this repository does not yet implement ACS middleware or claim ACS conformance. |
| [NIST AI RMF Generative AI Profile (AI 600-1)](https://airc.nist.gov/technical-reports/) | Voluntary risk management guidance for generative-AI systems, including testing, evaluation and governance. | Use to structure the risk register and evaluation plan; not a technical security certification. |

## 2. Implemented controls and evidence boundaries

| Security objective | Implemented control in this repository | Evidence that should be checked | Boundary that remains |
|---|---|---|---|
| Authenticate the API caller | Production service validates signed RS256 tokens against one configured HTTPS JWKS endpoint, exact issuer and audience, expiry/issue time, tenant claim and a configured access-token-purpose marker (default `token_use=access`). | `production_service/tests/test_clients.py`; `production_service/tests/test_oidc_integration.py`; Keycloak CI job. | The token-purpose marker must be configured by the trusted issuer in access tokens only. Bearer tokens are replayable if stolen; DPoP/mTLS and immediate token revocation are not implemented. |
| Prevent cross-tenant resource lookups | Tenant comes from the verified token. Resource lookup uses tenant-scoped rows; PostgreSQL RLS verifies a short-lived HMAC context bound to tenant, principal, backend PID and transaction ID. | `production_service/tests/test_postgres_store.py`; `production_service/tests/test_tenant_context.py`; runtime-role and key-forgery tests in CI. | This is tenant isolation, not per-principal row isolation by itself. OPA/application checks still enforce ownership. API/key, host, database-owner and superuser compromise remain outside this boundary. |
| Make authorization decisions fail closed | OPA decision requires a boolean result and the expected policy revision; missing/malformed/unavailable results are not permits. Policy uses tenant, resource status, scopes, tool registration and ownership/admin rules. | OPA policy tests; `production_service/tests/test_service.py`; real OPA CI smoke test. | A correct result depends on accurate issuer-controlled claims, trusted resource provisioning and controlled policy rollout. |
| Bind permits to the exact operation | Short-lived permits bind principal/tenant, action, resource, argument digest, trusted-context digest and policy revision. Execution re-fetches current context and the persistent store locks/checks resource state before claiming execution. | `production_service/tests/test_service.py`; `production_service/tests/test_postgres_store.py`; full Keycloak/PostgreSQL/OPA integration workflow. | Policy/context changes cannot be made atomic with every arbitrary downstream service effect. Keep the permit short-lived and test the deployed effect integration. |
| Avoid duplicate external operations | Durable local execution claims and idempotency keys; unknown outcomes are not automatically replayed. | Store concurrency/idempotency tests and adapter fault tests. | Exactly-once remote execution is not provided unless the downstream service has a compatible durable idempotency and reconciliation contract. |
| Classify upstream failures conservatively | The production HTTP adapter treats every non-2xx response as outcome-unknown by default. Specific 4xx responses can be classified as definite no-effect rejections only when a route explicitly declares a documented upstream guarantee. Redirects are not followed. | `production_service/tests/test_adapters.py`. | The route-level no-effect status list is a trust decision about the upstream contract. Verify it against the actual upstream implementation; do not infer it from the HTTP status family. |
| Provide a guarded agent reference path | Prototype tool boundaries validate allowlists, action/resource bindings, JSON argument schemas, budgets and trusted approval evidence. The reference runtime orders retrieval, model turns, tool calls and output release. | `prototype/tests/test_agent_boundary.py`; `prototype/tests/test_agent_runtime.py`; `prototype/docs/THREAT_COVERAGE.md`. | A host can bypass an in-process runtime unless all protected paths are integrated and downstream access is constrained. The reference runtime is not a vendor SDK or universal prompt-injection detector. High-impact tools requiring approval fail closed until a trusted approval integration exists. |
| Reduce unsafe content influence | Provenance-aware retrieval, untrusted labels for tool results, bounded context and output checks. | Prototype content-boundary and runtime tests. | Labels do not prove truth or stop semantic prompt injection. Output filtering is not comprehensive DLP; multimodal inspection is not implemented. |
| Limit HTTP request ambiguity and size | Production API rejects selected duplicate security/framing headers and conflicting request framing, and applies a bounded request body. HTTP adapters use configured routes, fixed upstream origins and no redirects. | `production_service/tests/test_http_boundary.py`; adapter tests. | Rate/concurrency controls, TLS ingress, DNS/egress restrictions, WAF/API gateway policy and service-level monitoring must be configured at deployment. |
| Preserve audit evidence | Production service writes structured audit events transactionally with relevant state transitions. Prototype includes hash-linked audit and an at-least-once outbox/export worker. | Production audit/store tests; prototype audit export tests. | Production-service audit is not immutable against database administrators and no independent WORM/SIEM destination is provisioned by this repository. The prototype exporter requires a separately operated idempotent receiver. |

## 3. Execution and retry contract

The safe client integration is deliberately two-phase:

1. Call `POST /v1/authorizations` and persist the returned `permit_id`.
2. Choose one idempotency key for the logical protected operation and persist it with the operation record.
3. Call `POST /v1/executions` with the same action, resource, arguments, permit ID and idempotency key.
4. If the request times out or the connection drops, retry only the execution request with the **same permit ID and idempotency key**. Do not obtain a new permit merely because the execution response was lost.
5. If PACA returns `status=unknown`, inspect the execution status and reconcile the downstream system before deciding whether a retry or compensating action is safe.

The convenience `PACAClient.authorize_and_execute()` method exposes an issued `permit_id` on execution-request errors, but applications that need process-restart-safe retries should use `authorize()` and `execute()` separately and durably store both identifiers.

A database transaction cannot atomically commit an arbitrary remote HTTP/API effect. A local idempotency record does not force the downstream API to deduplicate. No component should claim exactly-once delivery without a tested downstream contract.

## 4. Prioritized gaps before sensitive production use

These are deployment and engineering gates, not claims that the repository already provides them.

### Priority 0 — required for a real sensitive deployment

- Complete a deployment-specific threat model and independent security review.
- Use a real HTTPS identity provider and JWKS endpoint; verify the access-only token marker, tenant/role/scope governance, audience restriction, key rotation, expiry and revocation response.
- Use least-privilege database roles, separate signing/database credentials, remote PostgreSQL TLS peer verification, backup/restore drills and an approved key-rotation procedure.
- Put the API behind authenticated TLS ingress with request, tenant and concurrency limits. Do not expose unauthenticated OPA or database interfaces.
- Enforce egress allowlists and network segmentation. Every upstream route must be administrator-configured and its idempotency, redirect, timeout and failure semantics tested.
- Export security audit records to independently controlled, retention-protected storage. Restrict and monitor access to both the application and audit database.
- Integrate the real agent host, framework hooks, tool registry and downstream services. Prove with adversarial tests that every protected effect path is guarded and there is no direct bypass.
- Add approval gates for high-impact/destructive actions using a separately authenticated approval service. Never accept approval state from model output.

### Priority 1 — high-value hardening

- Add sender-constrained access tokens using DPoP or mutual TLS where the identity provider and client ecosystem support it; otherwise use tightly scoped, short-lived bearer tokens and document the residual replay risk.
- Establish a tested token revocation strategy. The current verifier validates token cryptography and claims but does not consult a per-token revocation/denylist service.
- Add tenant-level quotas, abuse monitoring, alerting, rate limits and resource-consumption controls at the trusted API ingress.
- Run fault-injection tests against each real downstream adapter, including timeout-after-commit, gateway 4xx/5xx after partial work, process termination, duplicate submission and reconciliation.
- Run a reproducible agent-security evaluation against relevant external tasks and conventional baselines. Report attack success, benign utility, false denials, latency, throughput and recovery; do not infer superiority from the repository's hand-authored tests.

### Priority 2 — interoperability and expanded assurance

- Add framework-specific adapters only when each adapter can preserve trusted identity, bind the complete effect-relevant request, enforce the guard at the actual executor boundary and demonstrate no-bypass behavior.
- Add an MCP server/client integration only with the MCP authorization and token-audience requirements implemented at the transport boundary; this repository currently does not claim MCP support.
- Evaluate adoption of the OWASP Agent Control Standard hooks and map applicable OWASP ASVS/AISVS requirements into testable acceptance criteria.
- Add multimodal and whole-plan/compositional attack coverage only with explicit implementations and independent test corpora.

## 5. Release evidence rule

A green CI run means only that the workflows declared in that exact commit passed. It does not establish a certification, independent audit, complete standards conformance, real-host integration, effectiveness against unknown attacks or production approval.

Every release or research claim should identify:
- repository and exact commit SHA;
- component and configuration exercised;
- test or benchmark corpus, version and seed;
- test result, skipped cases and failure handling;
- external systems and trust assumptions;
- residual risks and unsupported integrations.

Keep the separate `PACA-Plus-Plus-New` codebase and its benchmark evidence out of this repository's release claims.
