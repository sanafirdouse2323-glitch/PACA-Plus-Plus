# PACA++ threat model

**Status:** working threat model for the production-oriented integration scaffold, not a certification or independent security review.

## Assets to protect

- Protected downstream operations and the records/data they access or change.
- Authenticated subject identity, tenant membership, account status, and resource ownership.
- Policy decisions, trusted authorization context, and the correspondence between a decision and the operation actually dispatched.
- Downstream service credentials and OIDC/JWKS configuration.
- Durable operation state, idempotency keys, reconciliation decisions, and audit history.
- Availability of the API, OPA decision point, operation store, and downstream services.

## Adversaries and abuse cases

1. **Unauthenticated caller:** supplies a missing, malformed, expired, wrong-issuer, or wrong-audience token; attempts to invoke unregistered actions.
2. **Authenticated but malicious caller or compromised agent:** tries to read another user's resource, cross tenant boundaries, alter action/resource/arguments after a decision, replay a request, choose an arbitrary endpoint/handler, inject request-supplied roles/context, or make two users collide on an idempotency key.
3. **Stale or inconsistent authorization data:** user's status, ownership, tenant membership, or policy changes between the first check and the protected effect.
4. **Unavailable or malformed dependency:** OPA, the identity provider/JWKS service, trusted context store, PostgreSQL, or downstream API fails or returns malformed data.
5. **Interrupted or ambiguous remote effect:** a process dies, an HTTP request times out, or a response cannot be persisted after the downstream service may have committed the action.
6. **Operator or database misuse:** an operation is reconciled without evidence, audit rows are altered, credentials are over-privileged, or sensitive responses are exposed by logs or status endpoints.
7. **Malicious downstream or compromised PACA++ runtime:** ignores the idempotency contract, returns deceptive results, bypasses a registered handler, or executes effects outside the gateway.

## Trust boundaries

- **HTTP ingress → authentication:** only the verified JWT subject and issuer establish the caller identity. Client JSON cannot declare its own role, status, tenant, owner, policy result, Python callback, or destination endpoint.
- **Identity → authorization context:** roles, status, tenant membership, ownership, environment, and canonical resource mapping must come from trusted server-side data accessors, not from unverified token claims or request fields.
- **PACA++ → OPA:** the gateway sends a structured authorization input to a named OPA Data API decision. Only boolean result.allow == true allows an operation. Undefined, malformed, unavailable, or invalidly shaped decisions fail closed.
- **Authorization → effect boundary:** the gateway re-fetches context and re-evaluates OPA, then atomically claims a durable operation before calling a registered server-side handler. The baseline policy additionally binds the file path argument to the server-resolved canonical resource path.
- **PACA++ → downstream service:** a fixed-configured HTTPS endpoint receives a separately configured service credential and a derived idempotency key scoped to the verified principal. Redirects are rejected. The downstream service is still required to enforce its own permissions and durable deduplication.
- **Application → operation store/audit:** operation transitions and audit entries use database transactions and locking. Database access must be restricted to the gateway and privileged operators.

## Required security invariants

- No permit by default: missing attributes and no matching permit deny the request.
- Verified issuer, audience, signature, expiry, and subject are required before authorization.
- Trusted context is reloaded immediately before dispatch; a changed context cancels the issued operation.
- The baseline file.read policy requires active status, analyst role, matching owner, matching tenant, and exact equality between request path and trusted canonical path.
- A caller cannot select a handler or downstream URL. The action must match a server-side registered handler.
- A duplicate key with the same principal and same request cannot dispatch twice through this gateway. Reusing a key for different request material is rejected. Keys are principal-scoped; downstream keys are separately derived to the same scope.
- A downstream effect error or process interruption after the durable claim is not automatically retried. The outcome becomes unknown until an operator checks the downstream system and records a reconciliation.
- Status lookup is authenticated and returns only non-sensitive metadata to the initiating principal.
- OPA failure, invalid JSON, missing context, and authentication errors never cause a protected handler to be invoked.
- Audit records are hash-chained and verifiable, but not tamper-proof against a database administrator who can rewrite all rows and the head.

## Explicit assumptions and residual risks

- **Context-provider correctness is trusted.** The example launcher intentionally requires an application-specific provider. It must use authoritative data access, scope resource lookups by tenant, and map logical resource IDs to canonical resources. Incorrect provider code can grant access incorrectly.
- **Registered handlers are trusted code.** The gateway prevents callers from choosing handlers, but Python cannot force a buggy or compromised registered callback to use its ActionRequest correctly. Review each handler; downstream services should independently validate resource handles and permissions.
- **Policy/context are not transactionally locked with arbitrary remote effects.** Rechecking OPA immediately before the operation narrows the race, but policy or resource state may change after the decision and before a remote commit. High-risk actions need downstream enforcement, version/precondition checks, or a transaction boundary shared with authoritative state.
- **No generic exactly-once promise.** The durable store coordinates dispatch claims, but a crash or timeout may occur after the remote system commits. Strong idempotency requires the downstream system to honor the supplied key and retain its result. Otherwise, recovery requires manual evidence-based reconciliation.
- **Hash-chained audit is tamper-evident only.** An attacker with sufficient database privileges can rewrite the entire chain. For higher assurance, ship/checkpoint audit hashes to an independently controlled append-only service.
- **Identity freshness has bounds.** JWT validation checks signature, issuer, audience, expiry, and required claims. It does not implement universal token revocation. Status and roles are expected to be refreshed from the trusted context provider.
- **Availability/abuse controls are deployment responsibilities.** Put the HTTP API behind a trusted TLS reverse proxy with request/header timeouts, rate limits, request-size limits, and monitoring. Keep OPA and PostgreSQL on private networks; do not expose the OPA management API.
- **Operator reconciliation is privileged.** Restrict the paca-ops CLI, its host/session, and database credentials. reconcile-unknown must follow evidence from the authoritative downstream system; guessing can duplicate or incorrectly report a financial/security-sensitive action.
- **The SQLite store is for local/single-host use.** Use PostgreSQL or an equivalently coordinated durable store for multi-instance deployments.
- **No certification claim.** CI tests, Rego tests, and local integration tests are not a formal proof, third-party penetration test, standards certification, or guarantee that an arbitrary production deployment is secure.

## Existing verification coverage

| Risk / property | Verification |
|---|---|
| OPA fail closed, undefined and malformed response | tests/test_opa.py |
| Actual Rego owner, tenant, active-status and path matching | tests/test_opa_integration.py, policies/authz_test.rego |
| Verified JWT issuer, audience, signature and expiry | tests/test_jwt_auth.py |
| Context changes and policy denial prevent dispatch | tests/test_gateway.py |
| Cross-principal idempotency scope and concurrent claims | tests/test_gateway.py, tests/test_durable.py, tests/test_postgres_integration.py |
| Crash/timeout ambiguity does not trigger an automatic retry | tests/test_gateway.py, tests/test_durable.py |
| HTTP API request boundaries and protected status endpoint | tests/test_http_api.py, tests/test_full_stack_integration.py |
| Downstream endpoint fixation, credential separation, scoped key, redirect denial | tests/test_http_tool_adapter.py |
| Real JWT + live OPA + PostgreSQL + downstream API wiring | tests/test_full_stack_integration.py (integration environment required) |
| Audit tampering detection and operator reconciliation | tests/test_durable.py, tests/test_ops_cli.py |

This coverage is a starting point. It does not replace threat review, failure/chaos testing, workload-specific performance tests, downstream contract validation, and an independent security assessment.
