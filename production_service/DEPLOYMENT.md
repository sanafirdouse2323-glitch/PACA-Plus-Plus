# PACA++ production-service deployment guide

## What this deployment profile does

This guide and `paca_deploy.py` provide one repeatable setup and operating path for the existing production-service gateway. They do **not** replace or weaken the authorization architecture.

The database schema migration restores the canonical RLS policy and trigger set on the four authorization tables. Existing custom policies and non-internal triggers on those tables are removed during schema reapplication; these tables do not support operator-added policies or triggers.

The Compose stack still includes:

- the FastAPI gateway and verified access-token checks;
- OPA policy decisions on a private control-plane network;
- PostgreSQL permits, execution records, audit events and tenant RLS;
- the short-lived HMAC-signed tenant context;
- the configured protected-action adapters.

The helper automates local configuration generation, checks that the policy revision matches the checked-in policy data, validates the Compose configuration, and provides consistent start/status/log/stop commands. It does not provision an identity-provider tenant, create user claims or roles, configure external TLS/network infrastructure, migrate an existing database volume, or certify a deployment.

## Prerequisites

- Python 3.11 or newer. The helper uses only the Python standard library.
- Docker Engine or Docker Desktop with Docker Compose v2 supporting `up --wait`.
- An OIDC identity provider reachable over HTTPS.
- An access-token audience configured for this API (the default example is `paca-api`).

## First installation

Run these commands from the `production_service/` directory:

```sh
python paca_deploy.py init
python paca_deploy.py check
python paca_deploy.py up
python paca_deploy.py status
```

During `init`, provide the HTTPS OIDC discovery document address, usually ending in `/.well-known/openid-configuration`, and the audience that the identity provider will place in PACA access tokens. The helper retrieves the issuer and JWKS URI from that document, without following redirects.

The helper then creates `.env` with:
- independent random 32-byte values for the PostgreSQL administrator password, restricted runtime password and tenant-context HMAC key;
- the exact policy revision read from `opa/data.json`;
- the discovered issuer and JWKS URI;
- the audience and access-token purpose-claim defaults.

On POSIX systems the file is created with owner-only permissions (`0600`). The repository ignores `production_service/.env`; never commit this file or copy its secrets into prompts, logs, issue reports or source control. The helper refuses to overwrite an existing `.env` file.

For non-interactive setup:

```sh
python paca_deploy.py init \
  --discovery-url https://identity.example.org/realms/example/.well-known/openid-configuration \
  --audience paca-api
```

Replace the example address and audience with values from your own identity-provider configuration.

## Identity-provider configuration is still required

The helper reads public OIDC metadata; it does not create or configure an identity tenant. Before issuing PACA tokens, configure the provider to issue **RS256-signed access tokens** with:

- `sub`, `iss`, `aud`, `exp` and `iat`;
- an administrator-controlled `tenant_id`;
- the configured access-only purpose marker, by default `token_use=access`, present in access tokens and absent from ID tokens;
- administrator-controlled roles, tools and scopes required by the checked-in Rego policy.

The audience must match the value used with `init`. Never map tenant membership, scopes or privileged roles from user-editable profile fields. The current policy permits the `admin` role to bypass resource-owner matching, so grant that role only through an administrator-controlled identity assignment.

See [IDENTITY_PROVIDER.md](IDENTITY_PROVIDER.md) for the complete claim contract and Keycloak configuration example.

## Provision trusted tenant resources

PACA++ currently has no separate tenant registry table. The identity provider supplies the trusted `tenant_id` claim; each provisioned protected resource stores that exact tenant ID and the owner's exact access-token `sub`. Creating an identity-provider tenant, assigning users, and issuing trusted claims remain identity-administration tasks. The tool below creates only `protected_resources` rows; it does not create users, roles, scopes, API clients, files or external resources.

Install the service dependencies from this directory:

```sh
python -m pip install -e .
```

Create a reviewed JSON manifest outside source control. For example:

```json
{
  "resources": [
    {
      "tenant_id": "tenant-issued-by-your-idp",
      "resource_id": "smoke-file-001",
      "owner_id": "exact-sub-claim-of-the-owner",
      "kind": "file",
      "status": "active",
      "attributes": {
        "relative_path": "smoke/owner-check.txt"
      }
    }
  ]
}
```

The sample values are placeholders. Replace them with the exact trusted tenant ID and subject from your identity-provider configuration. For a `file` resource, place a non-sensitive test file at that relative path under the configured `PACA_FILE_ROOT` before running the smoke check. The path is trusted metadata, not a caller-supplied path.

Provision from `production_service/`:

```sh
python paca_provision.py resources \
  --manifest ./resources.json \
  --actor "operator@example.org"
```

With the local Compose deployment, the tool uses `docker compose exec` to connect to the database container over its local socket as the bootstrap database administrator; it does not publish a database port or put the administrator password in the API container. For a separately managed PostgreSQL deployment, set `PACA_ADMIN_DATABASE_URL` in the process environment to a dedicated administrative connection string containing `sslmode=verify-full`. That role must have `BYPASSRLS` (or superuser), INSERT privileges on `public.protected_resources` and `public.audit_events`, and `USAGE` on `public.audit_events_event_id_seq`. The tool explicitly rejects `paca_runtime` and roles without those privileges.

The provisioning operation is intentionally create-only. The manifest is limited to 500 resources, each attributes object is limited to 64 KiB, only `active` or `inactive` initial states are accepted, and duplicate tenant/resource identities fail rather than changing an existing owner or authorization context. The whole manifest and its audit rows are committed in one database transaction; any insert failure rolls the full batch back. Each resource receives an append-only `resource_provisioned` audit event containing the operator label and provisioning source. The `--actor` value is an operator-supplied audit label, not cryptographic proof of the person's identity; protect the host, shell access and administrative credential accordingly.

Do not add a provisioning API route or grant INSERT/UPDATE on `protected_resources` to the application role. Trusted resource ownership, status, kind and attributes are authorization inputs.

## Verify a live deployment end to end

After the API is ready and a non-sensitive smoke-test file has been provisioned, obtain three short-lived access tokens from your real identity provider:

- an owner token whose `sub` and `tenant_id` match the provisioned resource;
- a different subject in the same tenant with the same `file:read` scope, without the privileged `admin` role;
- a token for a different tenant.

All three tokens must otherwise satisfy the configured RS256, issuer, audience, expiry and `token_use=access` contract. Use dedicated test identities and never use real customer content. The verifier decodes the JWT claims payload only to validate the test scenario: the owner and same-tenant non-owner must both have `file:read`, neither may have the privileged `admin` role, their `tenant_id` values must match, and their `sub` values must differ. The cross-tenant token must have a different tenant. This local payload inspection is not authentication; the API remains responsible for validating each token's RS256 signature and claims. The verifier checks the API's specific `authorization_denied`, `resource_not_found` and `execution_not_found` response codes.

Set the values in the shell environment, not as command-line arguments:

```sh
export PACA_VERIFY_OWNER_TOKEN='<short-lived owner access token>'
export PACA_VERIFY_SAME_TENANT_NONOWNER_TOKEN='<short-lived same-tenant non-owner token>'
export PACA_VERIFY_OTHER_TENANT_TOKEN='<short-lived other-tenant access token>'
export PACA_VERIFY_RESOURCE_ID='smoke-file-001'
# Optional when .env is not available to this command:
export PACA_VERIFY_EXPECTED_POLICY_REVISION='paca-dev-2026-10-23'
# Optional; non-loopback HTTP is rejected:
export PACA_VERIFY_API_URL='http://127.0.0.1:8000'

python paca_deploy.py verify

unset PACA_VERIFY_OWNER_TOKEN PACA_VERIFY_SAME_TENANT_NONOWNER_TOKEN \
  PACA_VERIFY_OTHER_TENANT_TOKEN
```

The verifier sends a real `file.read` authorization request with the owner token, executes the resulting short-lived permit with a fresh idempotency key, and checks the persisted execution status. It then expects a 403 for the same-tenant non-owner and 404 for the other tenant attempting to access both the resource and the owner's execution. It checks the policy revision returned by the authorization response against the configured revision when that value is available. File contents are checked for a successful response but are never printed.

For a remote API URL, use HTTPS. The command does not mint tokens, configure the identity provider or provision the resource/file for you. It also does not exercise every protected action, every downstream adapter, remote OPA authentication, host-level bypass, backup/restore or operational controls. It is a deployment smoke check for one real file-read route, not a penetration test or production certification. Always use dedicated synthetic identities and data; avoid running it against customer resources. Treat the tokens as secrets and unset them after the check.

## Daily operation

Run these commands from `production_service/`:

| Command | Purpose |
|---|---|
| `python paca_deploy.py check` | Validate required settings, independent secrets, HTTPS identity URLs, policy revision and rendered Compose configuration. Does not start services. |
| `python paca_deploy.py up` | Recheck configuration, build images, start the stack and wait for the API readiness check. |
| `python paca_deploy.py status` | Show Compose container status and API liveness/readiness. |
| `python paca_deploy.py logs` | Follow the last 100 lines of Compose logs. |
| `python paca_deploy.py down` | Stop services while preserving database and file volumes. |

The API is bound to `127.0.0.1:8000`. It is not exposed directly to the public internet. `/healthz` checks process liveness; `/readyz` checks PostgreSQL signed-context verification and a real OPA deny-by-default decision with the expected policy revision.

The readiness check does not prove that an external identity provider will issue a suitable token, that a particular user/tenant/resource has been provisioned, or that every configured downstream effect works. Test those flows with synthetic identities and resources before use.

## Database initialization and existing data

On a **new empty PostgreSQL volume**, the official PostgreSQL image runs the mounted initialization scripts. They create the restricted runtime role, schema and grants, and provision the tenant-context HMAC key.

Initialization scripts do not run again for an existing database volume. The helper deliberately does not run schema migrations automatically during every start. This avoids silently changing an established database or running privileged migrations with the application runtime identity.

For an existing installation:
1. take a backup and verify that it can be restored;
2. follow the backup-first, administrator-only upgrade procedure in [the production-service README](README.md#upgrading-an-existing-volume-safely);
3. confirm the schema, grants and key provisioning completed before starting the API.

Do not use `docker compose down -v` or delete the named volumes to solve an upgrade problem. The `down` command above intentionally does not use `-v`.

## Remote services and protected effects

The supplied Compose stack runs OPA privately and uses the private Compose network for database/control-plane traffic. If you configure remote OPA, PACA requires HTTPS and a dedicated `PACA_OPA_BEARER_TOKEN`; the remote OPA operator must separately enable token authentication and a reviewed default-deny authorization policy. Sending a bearer header from PACA does not enable authentication on OPA.

Configured remote effect routes require HTTPS and a separate `PACA_API_BEARER_TOKEN`. These are injected service credentials. PACA does not acquire or refresh them automatically. Keep routes administrator-configured; never accept endpoint URLs or credentials from model output or API callers.

Keep `PACA_API_ROUTES_JSON={}` until you have reviewed and tested a specific downstream adapter contract. In particular, test idempotency, timeout-after-commit, redirects, error semantics and reconciliation. An ambiguous outcome is recorded as `unknown`; PACA cannot make an arbitrary remote effect exactly-once.

## Requirements before sensitive enterprise workloads

The Compose helper is a controlled deployment path, not a complete production platform. Before exposing sensitive workloads, the operating organization must also provide:

- authenticated TLS ingress and certificate management;
- network segmentation and outbound egress allowlists;
- rate, request-size, tenant and concurrency limits at the trusted ingress;
- a secrets manager and reviewed credential/key rotation and revocation procedures;
- backup retention, restore drills, migration approvals and disaster-recovery procedures;
- monitoring, alerting, incident response and security log review;
- independently controlled, retention-protected audit export;
- downstream-specific idempotency and reconciliation testing;
- actual host integration and adversarial no-bypass tests for every protected effect path;
- deployment-specific threat modelling and independent security assessment.

A green readiness check or CI workflow is not a penetration test, formal verification, certification, production approval or benchmark result. See [the repository security baseline](../docs/SECURITY_BASELINE.md) for the implemented controls and remaining gates.
