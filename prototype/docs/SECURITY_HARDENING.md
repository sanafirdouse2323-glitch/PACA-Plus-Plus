# PACA++ hardening layer: architecture, configuration, and claims

This guide documents the OPA-backed protected-effect path, trusted identity/context, durable permits, adapters, and audit outbox. See [Agent attack boundary](AGENT_ATTACKS.md) for the additional LLM tool-call layer.

## What this branch adds

The legacy **AuthorizationEngine** remains an in-memory, single-process research MVP. The hardening path adds a runnable ASGI endpoint for one allowlisted ticket-create action without silently rewriting the original compiler work. It includes OPA decisions that fail closed, a final authorization recheck, OIDC/JWKS verification, administrator-managed trusted context, fixed execution adapters, durable permits, replay handling, and audit export.

The agent boundary is complementary: it validates the model's tool proposal and fixes the action/resource mapping before the call reaches GuardedGateway. It does not replace OIDC, trusted context, OPA, the durable permit store, downstream idempotency, or the application's handling of untrusted tool output.

## Run locally

Requires Python 3.10+ and Docker for the OPA and PostgreSQL integration services.

~~~
cd prototype
python -m pip install -e ".[web,test]"
python -m unittest discover -s tests -v
python examples/demo.py
python experiments/run_experiments.py
docker compose up -d opa
docker compose --profile integration up -d postgres
python examples/opa_smoke.py
docker compose down
~~~

The OPA and PostgreSQL Compose ports are bound to loopback. PostgreSQL is enabled only by the integration profile; the example database password is for local tests only.

## Tool-boundary integration

Use the [agent attack boundary guide](AGENT_ATTACKS.md) for the supported API and an example wiring ticket creation to GuardedGateway. The tool allowlist, schema, action/resource mapping, gateway, adapter, and caller credential must come from trusted application configuration. An LLM must never be able to supply or change them. Treat all tool output as untrusted data, even when returned from an authorized operation.

## Guarantees and boundaries

- When all relevant effects go through GuardedGateway and a supplied adapter, missing/invalid policy decisions fail closed, permits are bound to the request fingerprint, and identity/trusted context/policy are rechecked immediately before the effect.
- The final policy/context recheck narrows but cannot atomically eliminate races with arbitrary remote side effects.
- Durable operation records prevent unsafe automatic replay within their persistence and idempotency guarantees. A crash during a remote effect can leave an unknown outcome; reconcile before retry.
- Audit hash chains and the transactional outbox are defense-in-depth, not tamper-proof storage against privileged database administrators.
- The agent boundary's in-memory call cache is scoped to one process/run. It is not a distributed store, formal proof, or substitute for the existing durable permit and idempotency system.
- These components do not claim to stop every prompt injection, prove universal security, provide exactly-once remote execution, establish standards compliance, or constitute an independent security audit. Sensitive workloads require an explicit deployment threat model, end-to-end tests, least privilege, monitoring, backups, incident response, and independent review.
