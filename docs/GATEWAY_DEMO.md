# Interactive PACA++ Gateway Console

## What this adds

The production-service FastAPI application serves a same-origin browser console at:

```text
http://127.0.0.1:8000/demo
```

The console calls the existing API. It does not implement a second policy engine or fabricate authorization outcomes.

It demonstrates the two-stage protocol:

1. `POST /v1/authorizations` — the service authenticates the bearer token, retrieves trusted resource context, evaluates OPA/Rego, and issues a short-lived permit only when the request is allowed.
2. `POST /v1/executions` — the service checks the same action, resource, arguments, current context and policy revision against the permit, claims execution/idempotency state, then invokes the configured adapter.
3. `GET /v1/executions/{execution_id}` — retrieves execution status for the authenticated principal and tenant.

## Prerequisites

This is a local/isolated test console, not a public hosted demo. Start and configure the production-service stack by following the main [production-service setup instructions](../production_service/README.md).

Before the browser flow can succeed, the running service needs all of the following:

- PostgreSQL, OPA and the FastAPI service running and ready.
- A real test OIDC issuer configured in the service, with an RS256-signed **access token** whose issuer, audience, signature, expiry and configured access-token-purpose claim validate.
- A trusted `tenant_id` and the appropriate scopes/roles/tools in issuer-controlled claims. The browser cannot set these claims.
- A resource row already provisioned by an administrator in `protected_resources`. The row must belong to the authenticated tenant and have a resource kind/status/owner compatible with the Rego policy.
- A configured execution adapter for the selected action. For file actions, the sandboxed file adapter uses the configured `PACA_FILE_ROOT` and the resource's server-side `attributes.relative_path`.

The form's default `file-1` value is used by the Python service unit-test fixture. It is **not** automatically inserted into a new PostgreSQL database. Use the resource identifier that an administrator has actually provisioned in your isolated test environment.

The committed Keycloak realm under `production_service/tests/identity/` is for automated local/CI integration tests. Its service-account clients and test secrets are not a browser login system and must not be exposed as a public identity provider or reused for production.

## Run and use the console

1. Follow the service's setup instructions and start the stack.
2. Open `http://127.0.0.1:8000/demo` from the same machine. The Compose configuration binds the API to loopback.
3. Select **Check service health**. Both `/healthz` and `/readyz` should respond successfully; readiness also checks the database and OPA dependencies.
4. Obtain a short-lived access token from your own configured test OIDC provider and paste it into the password field. Do not use an ID token or a production credential.
5. Select an action, enter a resource ID provisioned by the administrator, and provide a JSON object of arguments.
6. Select **Evaluate policy and request permit**. An allowed decision returns the real permit ID, expiry, policy revision and request ID from the API. A denied decision is shown as the API's error response.
7. After a permit is issued, select **Execute with permit**. The console submits the exact same action/resource/arguments with that permit and a stable `Idempotency-Key`.
8. For a response with an execution ID, use **Check execution status** to query the status endpoint.

Changing the action, resource or arguments clears the current permit and requires a new authorization request. The page does not automatically retry an uncertain effect. If an execution reports `unknown`, reconcile the downstream outcome before deciding whether another attempt is safe.

## What the responses mean

- `201` from authorization: OPA allowed the request and the service issued a permit.
- `403` from authorization or execution: the policy denied the request at that stage.
- `404`: the resource or caller-scoped permit/execution was not found.
- `409`: the permit is stale, its bound request/context changed, an execution is already in progress, or an idempotency conflict occurred.
- `422`: no configured adapter supports the requested action.
- `503`: an authorization dependency (such as the trusted context store or OPA) was unavailable; the service fails closed.
- `202` with `status: unknown`: the external effect's outcome cannot safely be determined. Do not blindly retry.

A successful authorization is not the same as a successful execution. The permit is short-lived and bound to the original request; execution rechecks the relevant state.

## Browser and security boundaries

- The page only calls relative, same-origin API paths; it does not accept an arbitrary API host.
- The bearer token is held in the page's input/memory only. It is not written to `localStorage` or `sessionStorage`, included in a URL, or printed in the response trace. Use **Clear session** when finished.
- The page uses `Cache-Control: no-store`, a restrictive Content Security Policy, and `Referrer-Policy: no-referrer`.
- The console itself does not authenticate users, mint tokens, provision resources, or assign trusted roles, scopes, ownership, tenant IDs or provenance.
- Use only synthetic data and a disposable database/file volume. `file.create` can create files in the configured sandbox. Do not connect this page to production.
- Do not expose the Compose service publicly. The current Compose setup binds the API to `127.0.0.1`; a public deployment would require a separately reviewed identity, network, ingress, rate-limit, resource-provisioning and data-isolation design.

## Scope of this demo

This console demonstrates the **PACA-Plus-Plus** FastAPI/OPA/PostgreSQL gateway flow. It is not a demonstration of the separate PACA-Plus-Plus-New provenance reference monitor, and it does not import that repository's code, attack simulations or benchmark results.

It also does not prove that every tool or side effect in an arbitrary agent host passes through PACA++. Host-level integration and bypass testing remain deployment work. The repository's automated tests and threat model define the implementation and evidence boundaries.
