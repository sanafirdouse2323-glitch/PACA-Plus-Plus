# Production-hardening phase 1: operation binding

## Scope

This change strengthens the research MVP; it does not make PACA++ production-ready. The code still has process-local permit storage, in-memory audit records, no trusted identity provider, no distributed consistency, and no external-effect adapter.

## Changes in this phase

- Added `authorize_operation` and `execute_operation` methods.
- An operation-bound permit records a principal identifier and SHA-256 digests of canonical JSON arguments and the authorization context, in addition to action, resource, policy version, policy-content fingerprint, and state version.
- Execution rejects a different principal, changed arguments, action/resource substitution, expired permits, replay, and stale policy/state before invoking the callback.
- Canonical argument encoding rejects non-JSON values and non-finite JSON numbers.
- Permit TTL must be finite, positive, and no greater than 300 seconds.
- The CLI now requires a principal identifier and uses the operation-bound API. Its effect remains simulated.
- Policy parsing snapshots validated JSON condition values; the engine takes its own validated policy snapshot and fingerprints both the declared version and policy content. Mutating the caller-owned input or Policy object cannot silently change the engine's active policy.

## Security caveats

The principal identifier is only a string at this layer. A real service must obtain it from authenticated identity middleware, not trust arbitrary client input. Hashes bind the serialized arguments and context snapshots but do not prove that a downstream tool executes those arguments or that the context is fresh. A real adapter must authenticate the principal, re-fetch/revalidate relevant context immediately before the effect, and pass the same canonical request to the effect implementation.

The in-process lock does not coordinate multiple processes or machines. If a remote effect partially succeeds and then times out, this engine cannot roll it back. Durable idempotency, transactional enforcement where available, and explicit reconciliation are still required.

The legacy `authorize` method can still issue a decision/permit for compatibility, but the execution boundary now rejects any permit that lacks principal and argument binding. All demo, CLI, and effect-path tests use the operation-bound methods.

## Verification

The unit tests cover principal mismatch, argument substitution, context changes, non-JSON arguments, non-finite and excessive TTLs, non-callable effects, policy mutation/fingerprinting, replay, stale policy/state, and local concurrent replay. GitHub Actions is configured to run unit tests, the demo, the operation-bound CLI, and deterministic scenarios. A configured workflow is not evidence that a run passed; verify the run status before treating these checks as green.
