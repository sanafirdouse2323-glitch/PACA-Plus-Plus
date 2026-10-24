# PACA++ prototype

This directory contains a research MVP and a production-oriented integration scaffold. It is **not yet a production-certified authorization service** and it does not parse or compile the repository's original ALFA/UCON+ language.

## Research MVP

The local engine demonstrates deny-by-default policy evaluation, deny override, short-lived permits, action/resource/context binding and in-process concurrency checks. Its effects remain simulated.

Run:

```bash
python -m unittest discover -s tests -v
python examples/demo.py
python experiments/run_experiments.py
python examples/authorize.py --policy examples/policy.json --context examples/context.json --action file.read --resource file:report-1 --principal-id demo-user --execute
```

## Production-oriented integration layer

- `opa.py`: OPA Data API decision client; undefined decisions and service failures do not allow access. Production startup requires the configured declared policy version, which is persisted in operation metadata and the audit chain.
- `identity.py`: JWT verification against a configured HTTPS JWKS URL, plus a trusted server-side context-provider interface.
- `gateway.py`: registered action gateway; re-fetches context and re-evaluates OPA immediately before dispatch.
- `http_api.py`: bounded HTTP JSON API with `POST /v1/execute` and authenticated operation-status lookup.
- `HTTPJsonActionAdapter`: sends calls only to a fixed configured HTTPS endpoint and rejects redirects.
- `durable.py`: durable SQLite store for single-host use and PostgreSQL store for coordinated multi-instance operation state. Includes principal-scoped idempotency, recovery states, strict unambiguous JSON parsing, encrypted cached responses, and a hash-chained audit log that cross-checks request identity/fingerprints, policy decision metadata, and cached response presence/content.
- `policies/authz.rego`: baseline example policy; intentionally narrow and must be adapted to verified business rules.
- `compose.dependencies.yml`: OPA and PostgreSQL dependencies for local integration.
- `.github/workflows/production-integration.yml`: checksum-pinned OPA validation plus live OPA/PostgreSQL integration tests.

Install the production dependencies and start the supporting services by following [the production deployment guide](docs/PRODUCTION_DEPLOYMENT.md).

## Critical guarantees and limits

The HTTP caller cannot supply policy context or choose a Python handler. The principal is authenticated from JWT claims verified against a configured issuer, audience, signing key and expiry. The trusted context provider maps the verified (issuer, subject) pair to an internal application user_id and loads status, role, tenant, resource owner and environment attributes from authoritative server-side data. OPA receives an issuer-scoped pseudonymous principal ID and the trusted internal user_id; resource ownership is compared within that internal-ID namespace, not against raw JWT sub. The gateway does not invent your database schema or treat client-provided claims as trusted authorization attributes.

Idempotency and state transitions are coordinated by PostgreSQL across service instances; SQLite is intended for local/single-host use. If a remote tool times out or an effect handler raises after dispatch starts, the operation is marked unknown and is not automatically retried. Operators must confirm the true remote outcome before reconciling the record.

Remaining deployment work includes implementing and reviewing the real context-provider plugin, configuring the real identity provider and downstream service, applying network/TLS/secret controls, adding external audit anchoring and operational metrics, setting up retention/migrations/backups, and testing in the target environment. Re-evaluation immediately before dispatch narrows but does not eliminate the race where policy changes after an OPA answer and before a remote side effect. The audit hash chain detects many accidental edits but does not prevent a sufficiently privileged database administrator from rebuilding it.

No CI or independent security review should be described as passing until its actual result is available.
