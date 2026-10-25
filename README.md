# PACA++ — research prototype

This repository is an early research scaffold for exploring authorization correctness in LLM-agent systems. The repository's original description refers to compiling ALFA/UCON+ policies to ASP and Cedar; that compiler integration is **not implemented by the current Python prototype**.

## Runnable components

The isolated [prototype](prototype/README.md) contains two paths:

- **Legacy MVP:** a small, in-memory JSON-policy engine with simulated effects, unit tests and deterministic scenarios. It remains useful for testing action-bound permit behavior and is not production authorization.
- **Hardening integration layer on this branch:** an OPA REST decision client and Rego policy, OIDC/JWKS JWT validation, trusted authorization-context retrieval, protected filesystem/HTTP adapters, single-host SQLite and multi-host PostgreSQL permit/idempotency state, hash-linked durable audit events, crash reconciliation, a runnable ASGI gateway for a fixed ticket-create route, and adversarial/integration tests.

The hardening code is deliberately separate from the legacy engine and original compiler work. See [the hardening architecture and limits](prototype/docs/SECURITY_HARDENING.md), [threat model](prototype/THREAT_MODEL.md), and [local verification report](prototype/docs/LOCAL_VERIFICATION_REPORT.md).

## Run the existing prototype

Requires Python 3.10 or newer.

~~~bash
cd prototype
python -m pip install -e .
python -m unittest discover -s tests -v
python examples/demo.py
python experiments/run_experiments.py
~~~

## Run the OPA integration path

Requires Docker and Python 3.10 or newer. See the complete OIDC/context-service wiring in the hardening guide.

~~~bash
cd prototype
docker compose up -d opa
python examples/opa_smoke.py
docker compose down
~~~

## Evidence and boundaries

Passing hand-authored tests shows only that the tested cases behaved as expected. It is not a formal proof, external-system benchmark, production security validation, standards compliance evidence, or proof of research novelty. The OPA local smoke test exercises a real OPA process when run as documented. CI has a separate step for this test.

The SQLite coordinator is for single-host deployments only; the audit hash chain is not tamper-proof; remote effects cannot be atomically committed with SQLite; and safe recovery depends on downstream idempotency or reconciliation. The sample OIDC and context adapters still require real, securely configured identity and authorization services. Do not expose an unauthenticated OPA endpoint publicly.

## Remaining work

1. Integrate and test the original ALFA/UCON+ policy syntax, parser, compiler, and evaluator; the prototype does not currently claim to implement these.
2. Coordinate policy rollout with protected-effect commits; provision and operationally secure PostgreSQL (the shared-store adapter is included) before multi-host deployment.
3. Add a downstream-specific integration environment that can test crash-after-commit, retry, and reconciliation semantics against actual protected services.
4. Send audit events to an independently controlled append-only sink, and complete deployment-specific security review and operational controls.
5. Compare with relevant existing systems and prior work before deciding whether any new research contribution is established.
