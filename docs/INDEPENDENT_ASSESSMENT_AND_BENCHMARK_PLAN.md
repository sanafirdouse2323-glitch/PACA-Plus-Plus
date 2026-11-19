# Independent security assessment and comparative benchmark plan

**Status:** planning document only — no independent assessment, certification, or comparative benchmark is claimed as completed.

**Prepared:** 19 November 2026

**Repository scope:** `sanafirdouse2323-glitch/PACA-Plus-Plus` only. This plan does not use, import, or make claims about `PACA-Plus-Plus-New`.

## 1. What this plan does and does not establish

This document defines work that can be commissioned and reproduced. It is not an auditor's report, penetration-test result, certification, benchmark result, or evidence that the system is ready for sensitive production workloads.

There are three distinct outcomes:

1. **Independent technical security assessment:** must be performed by a qualified external assessor who did not design or implement the controls being assessed, under an agreed scope and rules of engagement. The assessor must control or independently witness the test execution and issue the findings.
2. **Comparative effectiveness evaluation:** can be run by the project team using a predeclared, reproducible protocol, then independently reproduced or reviewed. A project-team run is not itself an independent security assessment.
3. **Organizational or service assurance:** depends on the service being operated, the organization, the customer requirements, and the applicable assurance scheme. There is no generic certificate that makes a software repository or codebase “production-certified”.

ISO/IEC 27001:2022 specifies requirements for an organization's information security management system (ISMS); certification concerns that management system, not a standalone software product. A SOC 2 examination reports on controls at a service organization within the defined system and examination scope. Neither should be represented as a product-level security certification. Select an assurance route only after the intended operating model and customer requirements are known.

## 2. Independent assessor requirements

Select an assessor with demonstrable application-security and infrastructure penetration-testing experience, plus experience with identity, authorization systems, API gateways, databases, and agent/tool execution boundaries.

The assessor should:

- have no material role in the PACA++ implementation, design, or claimed results;
- agree a written statement of work, scope, rules of engagement, test windows, permitted techniques, data-handling rules, and emergency contacts before testing;
- receive a pinned commit, architecture and threat-model documents, deployment instructions, and a clean, isolated test environment;
- independently select and execute test cases rather than simply sign off on the project's own CI output;
- record tool versions, configurations, evidence, limitations, and tests not performed;
- deliver prioritized findings with reproducible evidence, impact, affected component and commit, remediation guidance, and a retest outcome;
- disclose any conflicts of interest and identify subcontractors or automated services used.

Do not give an assessor production credentials, real customer records, signing keys, or unrestricted production access for this exercise. Use synthetic identities, synthetic resources, disposable infrastructure, and test-only credentials. Keep any proof-of-concept data and vulnerability evidence access-controlled.

## 3. Proposed assessment scope

The independent review should pin the exact release candidate and separately identify which controls belong to which component. Start with the deployed production-service path; treat the research prototype and LangGraph adapter as distinct work packages.

### Work package A — production authorization gateway

Review and test:

- RS256 JWT/OIDC validation, issuer/audience/token-purpose claim validation, JWKS handling, key rotation, token expiry and bearer-token replay assumptions;
- trusted tenant, principal, role, scope, tool, ownership, and resource-context sourcing;
- OPA authentication configuration, TLS, decision-path access control, policy-revision pinning, malformed/unavailable response handling, and default-deny behavior;
- permit binding to principal, tenant, action, resource, arguments, context, and policy revision;
- execution-time context and policy re-evaluation, permit revocation, atomic execution claim, replay/idempotency behavior, concurrent requests, and ambiguous outcomes;
- PostgreSQL RLS, signed tenant context, private signing-key custody, runtime-role privileges, migration/admin separation, recovery paths, and audit protections;
- each configured effect adapter, including file path confinement and symlink behavior, fixed HTTP route/origin constraints, DNS and egress behavior, redirect handling, downstream authentication, response limits, and uncertainty/reconciliation behavior;
- HTTP parsing/framing boundaries, request-size limits, rate/concurrency controls, deployment configuration, secret handling, logging, and operational recovery.

### Work package B — agent and framework boundaries

Assess these separately from the production gateway:

- prototype retrieval provenance, trust downgrade, argument validation, tool allowlists, output checks, approval behavior, and the documented limitations of the synchronous reference runtime;
- the separate inter-agent message boundary, including the host's sender-authentication contract and its in-memory replay limitations;
- the LangGraph adapter's tool allowlist, permit/idempotency journal, persistence configuration, thread concurrency, restart/resume, and uncertain-execution behavior;
- actual host integration and alternate execution paths. Attempt direct filesystem, database, HTTP/API, shell/subprocess, network, and unregistered-tool effects from the host environment where those paths exist;
- confirm which effects are actually mediated by PACA and which are outside the tested boundary.

A unit test showing that a guarded function rejects an input does not demonstrate that a deployed host cannot bypass that function. The assessor must examine the real executor and the surrounding trust boundaries.

### Work package C — packaging and browser console

Review the demo endpoint, nonce-based CSP, same-origin request behavior, token handling, request-state races, error reconciliation, package inclusion, and the actual deployment exposure. The existing static-client checks must not be treated as browser end-to-end tests.

### Explicit exclusions unless separately commissioned

- the separate `PACA-Plus-Plus-New` repository;
- the text-only archive snapshot of that repository;
- unsupported adapters or frameworks not present in the pinned release;
- production deployments or customer environments not explicitly included in the rules of engagement;
- formal verification or standards conformance not performed as part of the agreed scope.

The final report must list every exclusion and any assumption that materially limits the conclusion.

## 4. Minimum adversarial test themes

The assessor should develop independent test cases for at least the following categories. These are targets for testing, not claims that the current implementation already defeats them.

| Area | Example assessment question |
|---|---|
| Identity confusion | Can an ID token, wrong issuer/audience, wrong token-purpose claim, expired token, or token for another tenant be accepted? |
| Tenant isolation | Can a caller alter tenant context, resource IDs, database session state, or transaction context to reach another tenant's records? |
| Permit/request binding | Can action, resource, arguments, principal, tenant, context, or policy revision be changed after authorization and still execute? |
| Policy freshness | Can a permit survive a policy or trusted-context change that should revoke it? |
| Concurrency and replay | Can parallel requests, reused idempotency keys, permit replay, or process restart cause duplicate or unauthorized effects? |
| Effect adapters | Can path traversal, symlinks, route confusion, unsafe DNS/egress, redirects, response abuse, or malformed upstream behavior escape configured constraints? |
| Uncertain outcomes | Does timeout-after-commit or crash-after-effect cause an unsafe retry or an incorrectly reported success/failure? |
| Audit integrity | Can the runtime role alter or erase audit evidence, and are independent exports actually configured and verifiable? |
| Agent/tool bypass | Can a host execute an effect using a direct executor or unregistered tool without passing through the claimed authorization path? |
| LangGraph persistence | Do checkpoint/store failures, restart/resume, concurrent threads, and duplicate tool calls preserve the intended permit/idempotency binding? |
| Content and prompt injection | Are retrieved/tool messages kept as untrusted data, and can semantic or multimodal instructions influence an effect outside policy? |
| Operational controls | Are secrets, logs, ingress, egress, backups, migrations, rate limits, alerts, and recovery paths safe in the evaluated deployment? |

The report should distinguish exploitable vulnerabilities from design limitations, missing deployment controls, and untested assumptions.

## 5. Comparative effectiveness benchmark protocol

### 5.1 Research question

Under the same policies, authenticated identities, resource facts, operations, host application, and workload, does the complete PACA++ production-service path reduce unauthorized or stale protected effects compared with clearly defined simpler enforcement baselines, while preserving legitimate task completion and keeping latency and recovery overhead measurable?

This benchmark tests the documented production gateway mechanism. It does not establish that PACA is superior to every IAM, authorization, or agent-security product.

### 5.2 Arms to compare

Run all arms against the same deterministic synthetic host and adapter operations:

- **Arm A — unguarded host baseline (negative control):** the host dispatches the operation directly without a policy enforcement check. This measures the workload's built-in negative-control behavior; it is not a competing security product.
- **Arm B — one-shot OPA baseline:** the same OPA policy and equivalent trusted input facts are evaluated once before the operation. The baseline does not use PACA's request-bound permit, execution-time context/policy re-check, or durable execution/idempotency claim. Document the exact adapter and state semantics used; do not describe this as “OPA is insecure” or as a test of every OPA deployment.
- **Arm C — PACA++ production gateway:** the pinned production service, configured OIDC test issuer, OPA policy, PostgreSQL store/RLS and configured adapter are used through the actual authorization and execution API.

The policy, policy revision, input facts, allowed operations, identities, data set, adapter behavior, hardware, network topology, and failure-injection schedule must be held constant. If a baseline cannot support a scenario, report it as unsupported; do not silently exclude the scenario or score it as a PACA win.

### 5.3 Workload and attack scenarios

Use deterministic scripted requests and seeded state transitions; do not require an LLM provider or model sampling for the core authorization measurement. Include at least:

1. authorized benign operation with unchanged resource and policy;
2. unauthorized principal, tenant, action, resource, scope, or ownership;
3. argument or resource substitution after the initial decision;
4. resource ownership/status/context change between authorization and execution;
5. policy revision change between authorization and execution;
6. permit replay and cross-principal or cross-tenant reuse;
7. duplicate and concurrent execution with the same logical operation/idempotency key;
8. adapter timeout before effect, timeout after effect, process termination, and lost response;
9. direct host bypass attempts where the test host provides an alternate path;
10. malformed, oversized, or untrusted adapter inputs/results within the declared adapter contract.

For every scenario, declare the expected outcome before running it. Separate negative-control scenarios, unauthorized attack attempts, benign tasks, and fault/recovery scenarios in the report.

### 5.4 Metrics

Report counts and rates with denominators, not only percentages:

- **Unauthorized-effect success rate:** prohibited effects that actually occurred divided by prohibited attempts;
- **Benign completion rate:** successfully completed allowed tasks divided by allowed attempts;
- **False-denial rate:** allowed tasks incorrectly denied divided by allowed attempts;
- **Stale/replay acceptance rate:** stale permits or replayed operations that produce a prohibited additional effect;
- **Duplicate-effect rate:** duplicate external effects for one logical idempotent operation;
- **Unknown-outcome correctness:** cases correctly classified as unknown and reconciled without unsafe automatic retry;
- **Latency:** authorization-only and end-to-end p50, p95, and p99;
- **Throughput and resource use:** completed operations per second, CPU and memory at declared concurrency levels;
- **Recovery correctness:** correct final state after timeout, crash, restart, and retry/reconciliation cases.

A denial is not counted as a security success if it also incorrectly blocks a benign task. A reported unknown outcome is not a successful recovery until the downstream state is reconciled.

### 5.5 Reproducibility and analysis

Before executing the benchmark, freeze and publish:

- commit SHAs for all arms and test harnesses;
- exact policy files/revisions, configuration, dependency lockfiles, container/image digests, and hardware/runtime details;
- scenario definitions, test data generator, random seeds, request schedules, concurrency levels, and failure-injection points;
- exclusion rules, outcome oracle, metric formulas, and statistical analysis plan.

Use repeated independent runs and enough trials to report uncertainty. For binary outcomes, report numerator, denominator and a 95% confidence interval. For latency, report distributions and confidence intervals, not just a single average. Preserve raw machine-readable results, per-trial logs, analysis code, and a manifest of environment versions.

Do not choose or change scenarios after seeing which arm performs best. Publish negative results and unsupported cases. Any manual intervention, flaky trial, retry, or excluded observation must be recorded with a reason.

### 5.6 Interpretation rules

- A lower unauthorized-effect rate does not by itself establish overall superiority if legitimate utility, false-denial rate, or operational reliability materially worsens.
- Results apply only to the tested version, configuration, scenarios, and host integration.
- The one-shot OPA comparison is a specific baseline defined above, not a universal comparison with OPA or other policy engines.
- The negative-control arm is not a commercial competitor.
- Do not claim broad prompt-injection prevention from authorization-only scenarios.
- Do not claim production readiness, formal verification, certification, or independent assessment from this benchmark.

## 6. Required outputs

### Independent assessor report

1. executive summary and scope;
2. exact repository and commit identifiers;
3. architecture and trust-boundary diagram;
4. rules of engagement and environment description;
5. test methods, tools, and versions;
6. reproducible findings with evidence and affected components;
7. severity/risk rationale and remediation recommendations;
8. limitations, exclusions, and untested areas;
9. retest results and residual-risk statement.

### Comparative benchmark report

1. frozen protocol and benchmark manifest;
2. baseline definitions and policy/configuration equivalence;
3. scenario-level results with counts and confidence intervals;
4. utility, false-denial, latency, throughput, and recovery measurements;
5. raw results and analysis scripts;
6. deviations, missing data, failed trials, and limitations;
7. a restrained conclusion applying only to the measured workload.

## 7. Current status register

| Item | Status on 19 November 2026 | What changes the status |
|---|---|---|
| Repository CI | Automated workflows passed on the commits recorded in the relevant PRs; this is not an independent assessment. | Continue per-commit CI and preserve exact run/commit links. |
| Internal documentation review | Performed for selected architecture, credential, audit-export, agent-boundary, and demo consistency findings. | Keep review findings and fixes traceable to commits. |
| Independent security assessment | **Not completed; no external assessor report is present.** | Commission a qualified independent assessor, complete agreed scope, receive the signed report, remediate findings, and complete retesting. |
| Comparative benchmark | **Protocol defined here; no comparative benchmark result is claimed.** | Implement/run the frozen protocol, preserve raw results and analysis, and obtain independent reproduction or review before making superiority claims. |
| ISO/IEC 27001 certification | **Not claimed.** | Only relevant if an operating organization establishes an in-scope ISMS and completes certification through an external certification body. |
| SOC 2 report | **Not claimed.** | Only relevant if a service organization defines an in-scope system and completes the applicable independent CPA examination. |

## 8. References

- [NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final): guidance for planning, conducting, analyzing, and reporting technical security tests.
- [NIST AI RMF Generative AI Profile (AI 600-1)](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence): voluntary risk-management guidance relevant to generative-AI system evaluation.
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001): requirements for an information security management system; not a standalone software product certification.
- [AICPA SOC 2 description criteria](https://www.aicpa-cima.com/resources/download/get-description-criteria-for-your-organizations-soc-2-r-report): criteria used to prepare and evaluate the description of a service organization's system in a SOC 2 examination.

---

**Release rule:** Until the external assessment and benchmark have actually been completed, keep their status explicitly marked as outstanding. Do not convert a proposed plan, automated test, internal review, or green CI badge into an independent assurance claim.
