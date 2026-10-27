# PACA++ — authorization research prototype

PACA++ explores authorization correctness at the protected-effect boundary of LLM-agent systems: whether an authorization decision remains bound to the intended action, resource, policy and context when an effect is attempted.

**Important scope boundary:** the repository's original goal mentions compiling ALFA/UCON+ policies to ASP and Cedar. `compiler/transpiler.py` contains an experimental parser/emitter for a small policy subset; it is **not** a complete or standards-compatible ALFA/UCON+ compiler. The current regression tests verify parsing and generated-text invariants, not semantic equivalence between Cedar and ASP.

## What is in this repository?

- **`legacy_policy_engine/`:** the usable source snapshot from the earlier `PACA-Plus-Plus-New` repository, relocated as a separate legacy package to avoid replacing similarly named files in the current compiler, prototype, or production service. Its dependency manifest and tests are included. The legacy source is not yet wired into the root CI and should be validated independently before it is treated as part of the supported API.

- **`compiler/` and root `tests/`:** an experimental policy-subset parser and text emitters, with regression tests for the supported subset. Unsupported entity mappings and semantics fail explicitly instead of silently generating an output.
- **`prototype/`:** the legacy in-memory JSON-policy engine and simulated-effect CLI; a separate hardening path adds OPA, OIDC/JWKS verification, trusted authorization context, SQLite/PostgreSQL coordination, execution recovery, adapters, and a transactional audit outbox. The legacy engine and hardening path have different trust and durability properties.
- **`production_service/`:** a separately packaged FastAPI gateway combining verified JWT authentication, an OPA/Rego decision, resource-context lookup, PostgreSQL permits/execution records, and configured effect adapters. It is not the compiler, and it is not the same implementation as the `prototype/` gateway.

See each package's README and threat model before selecting the correct path for an experiment.

## Run the compiler regression tests

From the repository root:

```bash
python -m pip install lark-parser
PYTHONPATH=. python -m unittest discover -s tests -p "test_fuzzer.py" -v
```

These tests do not establish compiler equivalence, language conformance, or correctness for unsupported ALFA/UCON+ syntax.

## Run the research prototype

From `prototype/`:

```bash
python -m pip install -e ".[web,test]"
python -m unittest discover -s tests -v
python examples/demo.py
python experiments/run_experiments.py
```

The legacy engine and demo use simulated effects. The deterministic scenario file is a small, hand-authored test suite—not an external benchmark. CI checks that the checked-in scenario results are reproducible.

## Run the production-service scaffold

Start with [the production-service setup guide](production_service/README.md) and [its threat model](production_service/THREAT_MODEL.md). A real configured OIDC issuer/JWKS endpoint and trusted resource data are required. The local Compose stack is for controlled evaluation, not approval to handle sensitive workloads.

## What passing tests mean—and do not mean

CI results show that specified tests passed on a particular commit. They do not establish universal security, exactly-once execution across an arbitrary remote service, formal verification, independent security audit, standards compliance, or research novelty. An audit trigger/hash chain inside a database is not tamper-proof against a database administrator. Remote effects need downstream idempotency and reconciliation; deployment also needs least-privilege credentials, verified TLS where applicable, controlled OPA policy rollout, monitoring, backups, and incident response.

## Research status

The current evidence is a research/engineering scaffold. Before claiming a novel contribution, the supported semantics and threat model need a reproducible specification, differential tests against relevant systems, and a literature/artifact comparison. A successful build is useful implementation evidence, not proof of novelty.


## Consolidated repository note

The usable legacy policy-engine source is included under [`legacy_policy_engine/`](legacy_policy_engine/). The prior `PACA-Plus-Plus-New` repository remains unchanged as a backup for now; this avoids destroying the source history while the consolidation is validated. The archived snapshot under `archive/paca-plus-plus-new/` is historical material, not an importable working package.
