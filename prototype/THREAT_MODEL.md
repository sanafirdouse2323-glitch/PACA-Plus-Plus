# Legacy in-memory engine threat model

**Scope:** this document applies only to `prototype/src/paca_mvp/engine.py` and its in-memory `AuthorizationEngine`. It is not a threat model for the OPA/PostgreSQL hardening path or for `production_service/`.

## In scope

- Unmatched operations are denied by default.
- Explicit matching deny rules override permits.
- A permit is bound to exact action/resource, policy version, state version, and expiry.
- A permit cannot be consumed twice.
- The engine rejects action/resource substitution and stale policy/state before invoking its callback.
- The lock coordinates the in-memory engine in one Python process only.

## Assumptions

- Every protected effect passes through `AuthorizationEngine.execute`.
- The context passed to `authorize` is accurate and already trusted.
- Resource identifiers are stable and correctly normalized by the caller.
- One process owns the engine and permit store.
- Demo callbacks simulate an effect; a failing/partially completed external callback is not transactionally rolled back.

## Out of scope for this legacy engine

Authentication and identity proofing, trusted database-backed context, distributed coordination, durable execution state, production API/file adapters, durable/tamper-resistant audit, policy-language equivalence, complete URL/path/tool argument canonicalization, and formal model checking are not provided by this class.

## Safety statement

The tests are designed to check that, under the assumptions above, permits cannot be replayed or reused for a different action/resource and are invalidated by tracked policy/state updates. This is a design claim tested over selected cases, not a formal proof or an independent security guarantee.

For the separate integration path, see [the hardening guide](docs/SECURITY_HARDENING.md). For the separately packaged service, see [the production-service threat model](../production_service/THREAT_MODEL.md).
