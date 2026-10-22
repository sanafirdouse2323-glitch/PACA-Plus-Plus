# Initial threat model

## In scope
- Reuse of a permit for a different action or resource.
- Missing attributes and unmatched requests.
- Relevant policy/state version changes between decision and effect.
- Replaying a permit within one process.
- Deny-overrides semantics.

## Assumptions
- The application routes every protected effect through execute.
- Caller-supplied identity/context and resource identifiers are trusted and stable.
- A single process owns the engine and permit store.

## Out of scope
- A compromised Python process or direct side effects bypassing execute.
- Authentication/identity proofing, distributed coordination, durable tamper-resistant logs, cryptographic permits, policy-language equivalence, and formal model checking.
- Complete filesystem path, symlink, URL, or tool-argument canonicalization.

## Safety claim to test
Within one process, assuming all protected effects go through execute, a permit should not authorize a different action/resource, be reusable after consumption, or remain valid after the tracked policy/state version changes. This is a testable design claim, not an independently verified security guarantee.