# PACA++ Research Prototype

This directory contains the Python research prototype. It is separate from the top-level `compiler/` experiment. The Python package does **not** parse or compile ALFA/UCON+ policies.

## Requirements

- Python 3.10 or newer.
- PyJWT with cryptography support for configured RS256/OIDC verification.
- Docker only for the real OPA and PostgreSQL integration checks.

## Run locally

From this directory:

~~~bash
python -m pip install -e ".[web,test]"
python -m unittest discover -s tests -v
python examples/demo.py
python experiments/run_experiments.py
docker compose up -d opa
docker compose --profile integration up -d postgres
python examples/opa_smoke.py
docker compose down
~~~

The legacy demonstration uses simulated effects. The OPA/PostgreSQL commands exercise the configured integration path; they require the relevant containers and test configuration.

## Components

### Legacy MVP

`AuthorizationEngine` is a small JSON-policy example with a process-local permit store. It is useful for deterministic experiments, but it is not the hardened authorization path and its demo does not execute a real external effect.

### Hardened prototype gateway

The separate hardening path includes OPA decisions, OIDC/JWKS identity verification, server-side authorization context, SQLite single-host and PostgreSQL multi-host permit stores, guarded tool/API adapters, and a runnable ASGI gateway at `paca_mvp.service`. The optional `paca_mvp.context_service` reads authorization facts from administrator-managed PostgreSQL data. See [Security hardening](docs/SECURITY_HARDENING.md) for configuration and limitations.

### Audit delivery

Audit events and export intents are written transactionally. The `paca-audit-export` worker sends events at least once to a configured HTTPS sink. The receiver must durably deduplicate events and use independently controlled append-only or retention-protected storage. This repository does not provision that receiver. A local hash chain is tamper-evident, not tamper-proof against a database administrator who can also change its stored head.

### LLM-agent boundaries

The prototype contains three complementary boundary layers:

- [Agent tool boundary](docs/AGENT_ATTACKS.md): limits model-proposed tool calls to server-configured tools, actions, resources and argument schemas. Tool results remain untrusted.
- [Retrieval and output boundaries](docs/CONTENT_BOUNDARIES.md), composed by `GuardedAgentPipeline`: verify retrieval provenance and budgets, and check generated text before release.
- [Inter-agent message boundary](docs/INTER_AGENT_BOUNDARY.md): validates configured sender/recipient routes and labels accepted messages as untrusted. The host must authenticate the sender independently.

The [reference runtime](docs/AGENT_RUNTIME.md) now implements the ordering of retrieval, model turns, tool calls, and final-output release behind these boundaries. It is model-vendor-neutral; the host still supplies the actual model/retrieval adapters and must not expose bypass paths. It is not a universal prompt-injection detector. See the [threat coverage matrix](docs/THREAT_COVERAGE.md) for tested properties and remaining gaps.

### Separate production-service package

The repository also contains a separate implementation in [`production_service/`](../production_service/README.md), with its own [threat model](../production_service/THREAT_MODEL.md). Do not assume its identity/context model is identical to this prototype's internal-principal context service; follow each implementation's own setup and threat-model documentation.

## Security and deployment limits

- OPA decision failures, malformed or missing permit results, and missing active policy versions must fail closed.
- Identity verification requires a real, correctly configured issuer/JWKS endpoint. The trusted context provider must be administrator-controlled; caller-supplied roles or ownership claims are not authorization context.
- SQLite coordinates processes sharing one local database file. Use the PostgreSQL store for multi-host coordination.
- Durable permits and idempotency do not make a database transaction atomic with an arbitrary remote effect. Ambiguous external outcomes require downstream reconciliation; do not blindly retry them.
- The HTTP adapter uses configured routes and HTTPS. The downstream service must independently enforce authorization and honor its idempotency contract.
- The filesystem adapter confines access to configured logical resources, but it is not a sandbox for arbitrary executor code. Use least privilege.
- The sample Rego policy is illustrative. Production deployments need controlled policy rollout, secure OPA configuration, secret management, verified TLS where applicable, network controls, backups, monitoring, audit retention, incident response and deployment-specific testing.

These components are a hardening foundation—not a production-readiness claim, independent security audit, formal proof, standards-compliance claim, or proof of research novelty.
