# PACA++ architecture, design intent, and evidence boundaries

**Status:** research design and implementation overview; not a security certification or novelty claim.

## Research objective

Evaluate authorization at the protected-effect boundary of LLM-agent systems. The question is not merely whether a policy engine says “permit”; it is whether the operation that is actually committed is the same action/resource/arguments that were approved, whether stale permits and replays are rejected, and how failures around external effects are recorded and reconciled.

## Keep the implementations distinct

### 1. Root experimental compiler subset

`compiler/transpiler.py` parses a deliberately small ALFA-like grammar and emits Cedar-like and ASP-like strings for supported constructs. It preserves multiple AND conditions and escaped strings and refuses unsupported entity mappings, `verify_state` obligations, and ASP inequality. This is not a full ALFA/UCON+ parser/compiler. The six root regression tests validate parser/output invariants; they do not execute both generated policy languages or establish semantic equivalence.

### 2. Legacy `prototype/` engine

`paca_mvp.engine.AuthorizationEngine` is an in-memory, process-local JSON-policy engine. It uses default-deny, deny-overrides, action/resource-bound one-use permits, policy/state version checks, expiration, and a local lock around the simulated protected callback. Its demo does not call a real external tool or API. Do not attribute the legacy engine's guarantees to a distributed service.

### 3. `prototype/` hardening path

A separate path adds OIDC/JWKS authentication, OPA decision calls, server-trusted authorization context, SQLite for single-host state and PostgreSQL for coordinated state, execution recovery, filesystem/HTTP adapters, hash-linked audit events, and a transactional outbox for at-least-once audit export. Its guarantees depend on configuration and the downstream system. A local hash chain does not resist a privileged database attacker, and an uncertain remote outcome requires reconciliation rather than blind retry.

### 4. `production_service/` gateway

This separate FastAPI package uses an OPA/Rego policy, issuer/audience-verified RS256 tokens, resource records in PostgreSQL, durable permits/executions, and configured adapters. The resource owner identifier is compared with the verified OIDC subject; deployment data and issuer claims must follow that convention. Roles/scopes/tools in this service are taken from the verified token, so the issuer must control those claims. It must not be treated as identical to the separate prototype hardening/context-service path.

## Intended research questions

- **RQ1 — policy-subset correctness:** specify accepted syntax and semantics; add negative cases and differential tests that execute each backend against one independently specified corpus. Do not claim whole-language conformance from parser tests.
- **RQ2 — effect-boundary correctness:** measure rejection of action/resource/argument substitution, replay, expired permits, and stale policy/context/state.
- **RQ3 — persistence and recovery:** test cross-process/concurrent claims, crash-before-effect, crash-after-effect, uncertain downstream responses, retries, and reconciliation with a realistic adapter.
- **RQ4 — comparison and novelty:** compare supported semantics and threat models against relevant existing systems and prior work before naming a novel mechanism. A gap and novelty claim remain unestablished until that comparison is documented.

## Current evidence

The current tests include deterministic unit/adversarial cases, service tests, PostgreSQL-backed state tests, OPA/Rego tests, and an Actions workflow that exercises OPA. The deterministic scenario suite is small and hand-authored. Its checked-in result must be reproducible from `prototype/experiments/run_experiments.py`; a CI test enforces that contract. These results are not an external benchmark and cannot prove general security.

## Known boundaries

- Legacy permits are in-memory and process-local.
- The experimental compiler does not implement complete ALFA/UCON+ semantics or prove that Cedar and ASP output is equivalent.
- Trusted identity/resource provisioning is a configuration and deployment responsibility.
- PostgreSQL serializes PACA++ state changes but cannot share an atomic transaction with an arbitrary remote service.
- “Unknown” external outcomes require operator/downstream reconciliation.
- Audit triggers and local hash chains are not tamper-proof against privileged database operators.
- External OIDC/JWKS, TLS/egress controls, secrets, least-privilege roles, durable audit export, recovery drills, and independent security review are deployment gates.

The repository is a research/engineering scaffold. It does not claim formal proof, universal safety, standards compliance, production certification, independent security audit, or research novelty.
