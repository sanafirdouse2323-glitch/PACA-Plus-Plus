# PACA++ adversarial integration benchmark

## What is measured

The CI benchmark runs inside the production-service job after starting PostgreSQL, pinned OPA and a real Keycloak OIDC provider. It uses the actual FastAPI service, JWT verifier, PostgreSQL store, OPA policy decision, sandboxed file adapter, PACA host client and LangGraph `StateGraph`/`ToolNode` path.

The fixed adversarial scenarios exercise:
1. wrong-audience service token;
2. cross-tenant resource read;
3. same-tenant resource owned by another principal;
4. unknown tenant-scoped resource;
5. unregistered action (`shell.exec`);
6. cross-tenant execution-status lookup;
7. reusing a permit for a different action;
8. changing arguments after permit issuance.

The legitimate-task cases exercise one direct PACA-protected file read and one LangGraph tool call through the PACA client. A separate reliability case replays the same successful operation with the same idempotency key and checks that the same execution ID is returned.

The report records attack success rate, legitimate task success rate, reliability check outcome and client-observed p50/p95 latency. Attack success is defined as a forbidden permit or protected effect being accepted; merely receiving a denial or an error is not a successful attack.

## Baselines and comparison boundary

The report includes two modeled reference controls:
- `unguarded_no_authorization`: assumes every proposed request reaches the effect handler;
- `deny_all`: assumes every request is refused, including legitimate work.

These are analytical controls that illustrate the security/utility tradeoff. They are not external products, not measured competitor implementations, and not run as separate services in this CI job. The report labels them `executed_in_this_run: false`. A third-party comparison requires matched integrations and the same scenario set for each product.

## Output

When the OIDC integration test passes, the workflow uploads a JSON artifact named `paca-real-service-security-benchmark`. The artifact includes each scenario's status code and latency, the aggregate rates, the modeled baseline assumptions and a clear statement that the run is not an independent evaluation.

## Limitations

The model is a deterministic test model, and the OIDC test provider and PostgreSQL/OPA services are isolated CI fixtures. The benchmark does not include human red-team activity, arbitrary real-world agent prompt-injection corpora, external competitor systems, a real customer IdP, or a separate production host environment. It is a repeatable in-repository integration benchmark—not independent penetration testing, a certification or evidence of superiority over competing systems.


## Current benchmark evidence

The latest completed PR-event CI run is [43651201550](https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus/actions/runs/43651201550), testing PR branch head `6cb749b4e91758114933f22f68bcb5800f665217`. It recorded 0 successful attacks across 8 test scenarios, 2/2 legitimate tasks completed and a 1/1 same-idempotency-key replay check passed. Its combined request/task latency was p50 10.042 ms and p95 52.678 ms. The JSON artifact is `paca-real-service-security-benchmark` (artifact ID `14136062846`). Because this was a GitHub `pull_request` event, the artifact's `source_revision` is the synthetic PR merge-ref commit `9d81f73f144ca01fc73f9e6b6a7a941b6265c413`, while `ci_run_id` is `43651201550`. This is one small-sample repository integration run with a deterministic test model and test identity provider; the reference controls are modeled, not competing product measurements. It is not independent red-team evidence or a statistical production estimate. See [the CI run and artifact](https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus/actions/runs/43651201550) and [the independent evaluation runbook](../docs/INDEPENDENT_SECURITY_EVALUATION.md).
