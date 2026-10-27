# PACA++

Provenance-Anchored Continuous Authorization Framework for Autonomous LLM Agents.

## Overview

PACA++ explores authorization correctness at the protected-effect boundary of LLM-agent systems: whether an authorization decision remains bound to the intended action, resource, policy and context when an effect is attempted.

This repository contains distinct research and engineering paths, each with its own scope and maturity. Do not treat them as interchangeable implementations.

## Repository map

- **`compiler/` and root `tests/`:** experimental parser and text emitters for a limited policy subset. They are not a complete or standards-compatible ALFA/UCON+ compiler; tests do not establish semantic equivalence across ASP and Cedar.
- **`prototype/`:** a legacy in-memory JSON-policy engine and simulated-effect CLI, plus a separate hardening path with OPA, identity verification, trusted authorization context, persistence, execution recovery, adapters, and audit outbox. Review the package README and threat model for important boundaries.
- **`production_service/`:** a separately packaged FastAPI authorization gateway with verified JWT authentication, OPA/Rego decisions, resource-context lookup, PostgreSQL execution records, and configured effect adapters. It is not the compiler and is not the same implementation as the prototype gateway.
- **`archive/paca-plus-plus-new/`:** preserved source snapshot and recovery notes from the separate `PACA-Plus-Plus-New` repository. This is an archive, not an importable working package. See its `RECOVERY_NOTES.md` and `original-README.md`.

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

The legacy engine and demo use simulated effects. The deterministic scenario file is a small hand-authored test suite, not an external benchmark.

## Run the production-service scaffold

Start with [the production-service setup guide](production_service/README.md) and [its threat model](production_service/THREAT_MODEL.md). A real configured OIDC issuer/JWKS endpoint and trusted resource data are required. The local Compose stack is for controlled evaluation, not approval to handle sensitive workloads.

## What passing tests mean—and do not mean

CI results show that specified tests passed on a particular commit. They do not establish universal security, exactly-once execution across arbitrary remote services, formal verification, independent security audit, standards compliance, or research novelty. An audit trigger/hash chain inside a database is not tamper-proof against a database administrator. Remote effects need downstream idempotency and reconciliation; deployment also needs least-privilege credentials, verified TLS where applicable, controlled OPA policy rollout, monitoring, backups, and incident response.

## Research status

The current evidence is a research/engineering scaffold. Before claiming a novel contribution, the supported semantics and threat model need a reproducible specification, differential tests against relevant systems, and a literature/artifact comparison. A successful build is useful implementation evidence, not proof of novelty.
