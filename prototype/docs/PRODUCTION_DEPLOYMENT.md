# Production-oriented deployment guide

## What this code now provides

- **OPA decision point:** `OPAPolicyDecisionPoint` queries OPA's named Data API decision (`data.paca.authz.decision`). Missing/undefined decisions are denials; network, HTTP, and protocol failures fail closed. Startup preflight refuses an unavailable OPA, an undefined decision for empty input, or a decision that permits empty input.
- **Verified caller identity:** `JWTAuthenticator` validates signatures using a fixed asymmetric algorithm allow-list, a trusted HTTPS JWKS endpoint, issuer, audience, expiration and required claims.
- **Trusted context retrieval:** `CallbackContextProvider` calls application-supplied readers for subject, resource and environment attributes. No request-supplied context field is accepted by the HTTP API.
- **Protected execution:** `ProtectedToolGateway` registers action handlers on the server. It does not let a caller choose a Python callback or destination URL. It checks OPA, records an operation durably, re-fetches trusted context, re-evaluates OPA, then atomically claims before calling the handler.
- **Downstream API adapter:** `HTTPJsonActionAdapter` sends JSON to a fixed, configured endpoint over HTTPS; rejects redirects; sends the idempotency key and operation ID; and uses a service credential provider.
- **Durable coordination:** `PostgresOperationStore` uses a unique idempotency key and row locking for multi-process/multi-host coordination. Startup checks required tables and the audit-chain head. `SQLiteOperationStore` is useful for local development and single-host deployment; its database file is restricted to owner read/write on POSIX and symlink paths are rejected.
- **Audit and recovery:** operation state is persisted, cached JSON tool responses are Fernet-encrypted when configured, and audit events form a hash chain. Verification checks both the event chain and that each stored response matches the digest in its completion/reconciliation event. Stale in-progress operations can be marked unknown, and an operator can reconcile an unknown result after verifying the downstream system's authoritative record.

The baseline Rego policy deliberately permits only an active analyst reading a resource they own in the same tenant. Adapt it to your real business rules after reviewing the claims and resource attributes supplied by your actual application.

## Run locally

Requirements: Python 3.11+, Docker Compose, a reachable OIDC provider, and a real downstream API/context-provider implementation before exposing the service to users.

Install the optional production dependencies:

    cd prototype
    python -m pip install -e ".[production]"

Start supporting services (ports are bound to loopback):

    export PACA_POSTGRES_PASSWORD='replace-with-a-strong-local-secret'
    docker compose -f compose.dependencies.yml up -d

Configure the application using secrets from your secret manager or deployment platform:

    export PACA_OIDC_ISSUER='https://your-identity-provider.example/'
    export PACA_OIDC_AUDIENCE='your-api-audience'
    export PACA_OIDC_JWKS_URL='https://your-identity-provider.example/.well-known/jwks.json'
    # One-time schema/bootstrap step using an administrator or migration connection:
    export PACA_POSTGRES_ADMIN_DSN='postgresql://paca:ADMIN_PASSWORD@127.0.0.1:5432/paca'
    psql "$PACA_POSTGRES_ADMIN_DSN" -v ON_ERROR_STOP=1 -f migrations/001_runtime_roles_and_schema.sql
    # Configure these separate login credentials out-of-band through your secret manager/IAM.
    export PACA_POSTGRES_DSN='postgresql://paca_runtime:RUNTIME_PASSWORD@127.0.0.1:5432/paca'
    export PACA_OPERATOR_POSTGRES_DSN='postgresql://paca_operator:OPERATOR_PASSWORD@127.0.0.1:5432/paca'

The connection examples above are loopback-only. For a non-loopback PostgreSQL host, the store refuses to initialize unless the DSN explicitly sets `sslmode=verify-full` so TLS certificates and hostnames are checked; configure `sslrootcert` when your provider's CA is not in the system trust store. Do not downgrade remote connections to `prefer`, `require`, or `disable`.
    # Generate once in a trusted environment; store in your secret manager.
    # Keep the active key first; append retiring keys during rotation.
    export PACA_RESULT_ENCRYPTION_KEYS="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
    export PACA_OPA_BASE_URL='http://127.0.0.1:8181'
    export PACA_CONTEXT_PROVIDER='your_application.authz:build_context_provider'
    export PACA_FILE_READ_ENDPOINT='https://your-downstream-service.example/v1/read'
    export PACA_DOWNSTREAM_SERVICE_TOKEN='inject-this-from-a-secret-manager'

The module named by `PACA_CONTEXT_PROVIDER` must be available on `PYTHONPATH` and its factory must return an object implementing `load(principal, action, resource, arguments)`. `PACA_RESULT_ENCRYPTION_KEYS` is required by the production launcher and operator CLI: provide one or more comma-separated Fernet keys, with the current encryption key first and retiring decrypt-only keys after it. Generate the key once, keep it in a secret manager, and never regenerate it on each service restart; loss of a key makes affected cached responses unreadable. That implementation is application-specific and is intentionally not fabricated here: it must query the authoritative user/tenant/resource store. The example policy expects the returned subject attributes to contain `user_id`, `status`, `role`, and `tenant_id`, and the resource attributes to contain `owner_id`, `tenant_id`, and `canonical_path` (for the example `file.read` policy). `user_id` must be an authoritative, stable internal account ID resolved using both the authenticated OIDC issuer and subject; `resource.owner_id` must use the same internal ID namespace. Do not compare resource ownership directly with raw JWT `sub`, which is only unique within an issuer. The canonical path must be resolved from authoritative resource storage; do not copy it from the request.

Start the HTTP API (defaults to loopback only):

    paca-gateway

The service's HTTP listener does not provide TLS itself. Keep the default loopback bind when a same-host reverse proxy is used. A non-loopback `PACA_BIND_HOST` is rejected unless `PACA_TRUSTED_INGRESS_TERMINATES_TLS=true` is explicitly set. Set that acknowledgement only after configuring a trusted TLS-terminating ingress and protecting the ingress-to-service network hop; the flag does not configure or verify TLS and is not a substitute for network controls. Do not expose the raw HTTP listener to untrusted networks.

Example operation request:

    curl --fail-with-body \
      -H 'Authorization: Bearer <OIDC_ACCESS_TOKEN>' \
      -H 'Content-Type: application/json' \
      -H 'Idempotency-Key: read-report-2026-001' \
      -d '{"action":"file.read","resource":"file:report-1","arguments":{"path":"report-1"}}' \
      http://127.0.0.1:8080/v1/execute

Use the returned operation ID to query non-sensitive status:

    curl -H 'Authorization: Bearer <OIDC_ACCESS_TOKEN>' \
      http://127.0.0.1:8080/v1/operations/<OPERATION_ID>

The `Idempotency-Key` value must uniquely identify one logical operation for the authenticated principal. Keys are scoped to that principal, so different principals can use the same client key without colliding. Reusing a key for a different action/resource/arguments/context for the same principal is rejected.

## Context provider contract

Implement a trusted provider in your application:

    class YourContextProvider:
        def load(self, principal, action, resource, arguments):
            # Resolve the application's internal user row by BOTH principal.issuer and
            # principal.subject; OIDC sub values are not globally unique.
            # Put that row's stable internal primary key in subject_attributes["user_id"].
            # Resolve resource.owner_id from the same internal user-ID namespace.
            # Never take user_id, role, tenant, owner, status or permissions from request JSON.
            # Return TrustedAuthorizationContext(subject_attributes=...,
            #     resource_attributes=..., environment=...)
            ...

The `resource` identifier is caller-supplied input; the lookup must enforce tenant scoping and return an empty/denied resource context when it does not exist or the principal must not discover it. The baseline file-read policy additionally requires `arguments.path` to equal the server-resolved `resource.canonical_path`, so authorization for a logical resource cannot silently be reused to read a different caller-selected path. Real file integrations must still resolve and enforce the trusted resource handle/path at the downstream effect boundary, including symlink and canonicalization rules. Do not return secrets or unnecessary personal data to OPA.

## Tool/API adapter contract

Register a handler only in trusted server-side setup. For example, `serve.py` registers only `file.read` and maps it to one environment-configured downstream endpoint. Do not build an endpoint URL from user-supplied hostnames or forward the user's bearer token to a downstream API. The adapter sends a separately configured service token and a derived downstream idempotency key scoped to the verified issuer, principal, and client key. The raw client key is not forwarded downstream; store the service token as a secret and rotate it. OPA receives only an issuer-scoped pseudonymous principal ID plus trusted internal user_id; the raw OIDC subject is not copied into the OPA input.

The downstream service should:
- authenticate PACA++ as a service;
- perform its own authorization for the target resource;
- treat the received principal-scoped idempotency key as unique and retain its result durably;
- return a JSON response within the configured size limit; and
- expose an authoritative status/log lookup for operator reconciliation.

## Operator recovery commands
The gateway uses `PACA_POSTGRES_DSN` with the restricted `paca_runtime` role. The local operator CLI uses `PACA_OPERATOR_POSTGRES_DSN` and a distinct `paca_operator` role. These roles have column-limited UPDATE rights only for mutable operation-state fields; immutable request identity/fingerprint fields cannot be updated. They can append audit events and advance the chain head, but are not granted UPDATE or DELETE on prior audit-event rows. Schema creation is a separate administrator/migration operation through `migrations/001_runtime_roles_and_schema.sql`; do not run the gateway with a database-owner or superuser DSN. The sample SQL assumes the database is named `paca`; adapt it before running against a differently named database.


Install the production package, then configure a restricted operator shell with one backend:

    export PACA_OPERATOR_POSTGRES_DSN='postgresql://paca_operator:OPERATOR_PASSWORD@127.0.0.1:5432/paca'
    # or, for a single-host SQLite deployment:
    export PACA_SQLITE_PATH='/var/lib/paca/state.db'

Verify that the stored audit chain has not been altered:

    paca-ops --backend postgres verify-audit

Mark in-progress operations older than a carefully selected threshold as unknown; this never resubmits the external effect:

    paca-ops --backend postgres recover-incomplete --older-than-seconds 120

Inspect an operation's non-sensitive metadata:

    paca-ops --backend postgres show-operation --operation-id <32-hex-operation-id>

After checking the downstream system's authoritative evidence, reconcile an unknown outcome. Successful outcomes require the verified JSON response, which is durably stored and later replayed for the same authorized request:

    printf '%s' '{"remote_id":"r-123"}' | paca-ops --backend postgres reconcile-unknown --operation-id <32-hex-operation-id> --outcome succeeded --reason ticket-INC123-verified --response-stdin

This CLI is a privileged local tool; it is not exposed through the public HTTP API. Restrict its database credentials and retain operator-session/audit records. Reconciliation is only as trustworthy as the evidence and operator process used to select the outcome.

## Failure and recovery semantics

A permit/operation row is claimed atomically before dispatch. If the handler raises after dispatch begins, PACA++ marks the operation `unknown` and refuses to replay it automatically. A timeout cannot reveal whether a remote action committed. Operators must inspect the downstream system, then use the store's `reconcile_unknown(...)` method with outcome `succeeded` or `failed` and a recorded reason. Do not reconcile by guessing.

Run `store.recover_incomplete(older_than_seconds=...)` during a controlled recovery process after checking the configured threshold is longer than legitimate action duration. It conservatively marks stale in-progress entries unknown; it does not retry the effect.

## Test and validate

    python -m unittest discover -s tests -v
    python examples/demo.py
    python examples/authorize.py --policy examples/policy.json --context examples/context.json --action file.read --resource file:report-1 --principal-id demo-user --arguments-json '{"path":"report-1","mode":"read"}' --execute
    python experiments/run_experiments.py

The GitHub Actions production integration workflow pins and checksum-verifies OPA v1.21.4 (the release pinned for this review), runs `opa check` and `opa test`, starts OPA and PostgreSQL, applies the database migration, assigns separate test credentials, and exercises data access through the least-privileged PostgreSQL runtime role. The Python suite includes live OPA policy tests, end-to-end OPA/PostgreSQL/HTTP-adapter tests, JWT/context-provider tests, replay and recovery cases, SQLite file-permission checks, cached-response audit-tampering checks, duplicate-key/non-finite JSON rejection, repeated security-header rejection, and redirect rejection.

## Production limitations that remain

This phase does not make the project certified or ready for an arbitrary production environment:

1. **Context schema and business rules remain application-specific.** The real user/resource database readers must be implemented and reviewed.
2. **OIDC configuration must be validated against your identity provider.** The code verifies JWTs but does not provision accounts, groups, roles, or sessions.
3. **Generic exactly-once external effects are impossible to promise.** The gateway provides coordinated at-most-once dispatch attempts and conservative unknown-outcome recovery. Stronger guarantees require downstream idempotency or a shared transaction.
4. **Policy-update atomicity with external execution is not guaranteed.** OPA is re-queried immediately before dispatch, but a policy can change after evaluation. Sensitive systems need versioned policy rollout and/or enforcement inside the same trusted transaction boundary.
5. **The hash chain is tamper-evident, not tamper-proof.** A database administrator who can rewrite all rows and the head can rebuild it. Export/checkpoint audit hashes to an independently controlled append-only system for stronger assurance.
6. **The server is HTTP and binds to loopback by default.** If deployed across hosts, terminate TLS at a trusted reverse proxy, protect that hop, and expose only the intended route. Never expose OPA's management interface to untrusted clients.
7. **Operational hardening still needs deployment-specific work:** secret management, migrations, backups, retention policy, metrics, alerting, rate limits, load/chaos testing, dependency and container digest pinning, independent threat review, and recovery drills.

Do not report production readiness until the downstream integration, context provider, identity configuration, CI results, and deployment controls have been verified in the target environment.
