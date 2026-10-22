# PACA++ Full Prototype Design Specification

**Status:** Research prototype specification and implementation scaffold. It does not claim novelty, production readiness, or standards compliance.

## Objective
Evaluate whether authorization decisions remain correct through the protected-effect boundary: not only whether a policy engine returns permit, but whether the committed effect matches the authorized request and whether policy/state changes invalidate stale approvals.

## Architecture
1. Agent/request generator proposes an action; it cannot self-authorize.
2. Request normalizer should canonicalize action, resource, identity, and arguments. Platform-specific canonicalization is not yet implemented.
3. Policy decision point evaluates explicit rules over supplied context, using default-deny and deny-overrides.
4. Permit manager creates a short-lived, one-use permit bound to action, resource, policy version, and state version.
5. Protected-effect gateway validates and consumes the permit immediately before the callback.
6. Tool sandbox initially simulates side effects; external tools should be added only after the boundary is tested.
7. Audit recorder captures decision and effect lifecycle events.
8. Experiment runner executes deterministic adversarial scenarios.

## Research questions and evidence
- **RQ1 — semantic correctness:** policy validation/evaluation tests and, after integration, differential tests for existing PACA++ parser/compiler/evaluator.
- **RQ2 — effect-boundary correctness:** action/resource substitution, replay, expiry, stale policy, and stale state tests.
- **RQ3 — comparison:** run the same supported scenarios against selected baseline systems, recording unsupported features and assumptions.
- **RQ4 — novelty decision:** introduce a new mechanism only if a specific, important residual gap remains after literature and artifact comparison. Otherwise report formalization, conformance testing, reproducible evaluation, or comparative analysis.

## Current MVP properties
- Default deny when no permit rule matches.
- Missing attributes fail closed, including ne.
- Exact action/resource matching at execution.
- Deny-overrides.
- One-use permits and expiry.
- Policy/state version checks.
- Local lock around validation and callback.

## Evaluation protocol
Measure unauthorized effect rate, false-denial rate, decision accuracy, effect outcome accuracy, stale-permit rejection, replay rejection, and median/p95 latency. Publish scenario definitions, raw outcomes, versions, and limitations. A toy scenario suite is not a benchmark against external systems.

## Limitations
The permit store is in-memory and process-local. The code assumes trusted context and stable resource identifiers. The local lock does not provide distributed atomicity or roll back external effects if a callback partially fails. There is no production identity provider, durable tamper-resistant audit, full policy DSL, external tool adapter, or formal proof. Test results do not establish universal safety, standards compliance, or research novelty.