# PACA++ production-service deployment guide

## What this deployment profile does

This guide and `paca_deploy.py` provide one repeatable setup and operating path for the existing production-service gateway. They do **not** replace or weaken the authorization architecture.

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
