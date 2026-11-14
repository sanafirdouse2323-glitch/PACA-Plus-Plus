# Independent security evaluation and comparative benchmark runbook

## Status and evidence already collected

The repository CI has a completed real-service integration benchmark run:

- Workflow run: [43651938764](https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus/actions/runs/43651938764)
- Branch head: `5542ed60a26221b3639042e10181d3287d572523`
- Tested merge-ref commit: `ed4a240051b610aed6562e049c9c1259ba607d32`
- Artifact: `paca-real-service-security-benchmark` (artifact ID `14136547107`)
- Observed: 0 successful attacks in 8 attempted scenarios; 2/2 authorized tasks completed; 1/1 same-key replay check passed.
- Combined request/task latency in this one run: p50 7.207 ms, p95 42.048 ms.

The run exercised the repository's FastAPI authorization/effect gateway, signed tokens from a real Keycloak test container, a pinned OPA server, a PostgreSQL service container, the sandboxed file adapter, the host-side PACA client and a LangGraph StateGraph/ToolNode integration.

**This is repository CI evidence, not an independent security evaluation.** The LangGraph model is deterministic test code, not a production LLM. The OIDC provider and database are ephemeral fixtures. Eight attempts and two legitimate tasks are not a statistically meaningful estimate of production attack success or utility. The report explicitly labels the no-authorization and deny-all reference controls as modeled, not executed competitor implementations.

## Independent evaluator requirements

The evaluator must be separate from the implementation team and must control the test environment, attack selection, execution, analysis and final report. Record evaluator identity, conflicts, repository commit, container image digests, policy bundle digest, configuration, test corpus version, random seeds, model/provider versions, dates and deviations.

Use a staging deployment that mirrors production topology but contains synthetic data and no production credentials. The evaluator must not receive private signing keys, database superuser credentials, cloud administrator credentials or access to production user data.

### 1. Host-level bypass assessment

Run from the actual host/agent runtime deployment—not only a unit-test or sample Docker topology.

Test direct:
- filesystem access outside allowed roots, symlinks, hard links, mount and namespace edge cases, file descriptor reuse, path races and direct host syscalls;
- database network access, runtime credentials, connection strings, role escalation, RLS context forgery, direct SQL writes and bypass of the application service;
- downstream API access, alternate DNS/IP routes, IPv4/IPv6, proxy variables, redirects, service-mesh paths and cloud metadata endpoints;
- Docker/container runtime sockets, privileged capabilities, writable mounts, host PID/network namespaces, environment secrets and process inspection;
- every registered tool, framework callback, retry path, background worker and alternate executor.

For each attempt, record command/request, caller identity, path taken, policy decision, resulting effect, durable audit event, status, latency and supporting host/network/database evidence. A denied HTTP response alone is insufficient if the protected effect occurred by another route.

### 2. Identity, OAuth and OPA

Verify at the actual authorization server and deployed OPA:
- exact issuer and audience checks, client identity and subject, required scopes, token type, expiry, not-before and algorithm pinning;
- wrong-audience, wrong-issuer, wrong-client, wrong-scope, expired, malformed, replayed and opaque-token cases;
- RFC 8707 resource indicators are accepted by the token endpoint and produce tokens whose signed audience claims are checked by the recipient;
- JWKS rotation, unknown key IDs, key rollover, revoked/disabled clients, token refresh, TLS validation, redirects, proxy configuration and outage behavior;
- OPA token authentication and API authorization are enabled on every remote listener, the system.authz policy is default-deny, only the PACA decision route is allowed, and no alternate unauthenticated listener is reachable.

Test the downstream API's own authorization and audience validation independently. A resource indicator sent to an OAuth token endpoint is not proof that a recipient validates the resulting token.

### 3. Ledger, checkpointing and crash recovery

Exercise multi-process and multi-host operation with the same and different thread IDs. Inject process termination at each point: before authorization, after permit issuance, before ledger commit, after ledger commit, before effect call, after effect call but before result persistence, and during checkpoint recovery. Race duplicate idempotency keys, changed arguments, expired permits, duplicate tool-call IDs, and database connection failures.

The evaluator must determine whether the operation ledger and LangGraph checkpoint store recover consistently without issuing a second external effect. Include downstream reconciliation for ambiguous outcomes; do not infer atomicity between PostgreSQL and arbitrary remote systems.

### 4. Independently controlled audit retention

Provision the external archive in a separately administered account/security boundary. The evaluator should control or witness bucket-policy, IAM, Object Lock, KMS and retention configuration. Verify:
- versioning and Object Lock are enabled;
- each event is written with COMPLIANCE retention and SSE-KMS;
- the exporter cannot delete objects/versions, bypass retention, change bucket policy, or administer the KMS key;
- attempted object deletion, replacement, metadata tampering, retention shortening, role escalation and KMS disablement are denied or detected;
- export lag, missing events, digest mismatches, object-key collisions, retries, restore and evidence retrieval are monitored and tested.

CI's fake S3 client validates request construction and retry logic only. It does not establish a real AWS account boundary or effective IAM/KMS policy.

## Matched comparative benchmark protocol

Do not compare PACA++ with another product from marketing material, modeled assumptions or different experiments. The evaluator must select actual competing defenses and implement each one in the same harness with equivalent coverage.

At minimum compare:
1. unprotected host execution (control);
2. deny-all authorization (security/utility lower bound);
3. PACA++ at the exact evaluated commit;
4. at least one selected, documented agent-security defense, with exact release/configuration and all required enforcement integrations.

Use a published agent benchmark such as AgentDojo only after pinning its exact release/commit, task-suite version and attack set. Where the competitor cannot protect a specific tool or effect, mark that scenario unsupported; do not count it as a successful defense. Ensure the PACA adapter and each comparator mediate the same effects rather than comparing PACA's full gateway against a prompt-only filter with incomplete tool coverage.

Keep model provider, exact model version, system prompt, temperature, token limits, context, task data, attack strings, seeds, retries, budgets and environment constant. Randomize system order and repeat enough trials to estimate uncertainty (recommended minimum: 5 independent seeds per task/model pair; justify a larger sample for claims).

Report:
- attack success rate overall and per attack family, with numerator/denominator and 95% confidence intervals;
- legitimate task success / utility and task-level failures;
- false denials and false permits;
- p50/p95 latency, throughput, token usage and cost;
- effect duplication, unknown outcomes, crash-recovery failures and audit completeness;
- results by model, suite, task difficulty and attack family.

Publish raw per-attempt JSONL, analysis scripts, seeds, pinned dependencies, environment manifests, commit identifiers and confidence-interval calculations. The final report must include null results, unsupported scenarios and deviations—not only successful tests.

## Release gate

Do not state that PACA++ is more effective than competing systems, production-ready, bypass-proof or independently validated until an independent evaluator has run the host-level tests and the matched benchmark protocol and published its evidence. Repository CI passing is a necessary regression gate, not that independent validation.
