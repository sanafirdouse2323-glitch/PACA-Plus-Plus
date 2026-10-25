# PACA++ production-service scaffold

This directory contains a separate FastAPI service that combines JWT verification, trusted context lookup, OPA policy decisions, PostgreSQL operation state, and fixed server-configured effect adapters.

**Status:** engineering scaffold for controlled evaluation. It is not production-certified, and these instructions do not replace an organization-specific security review.

## Requirements

- Docker Engine and Docker Compose v2
- A configured OIDC provider that issues tokens for the configured audience
- A trusted identity/context and resource model
- For external API actions, a downstream API that supports durable idempotency and reconciliation

## Local setup

1. Copy the example environment file and replace the database password with a fresh random value:

   ~~~sh
   cp .env.example .env
   openssl rand -hex 32
   ~~~

   Put the generated value in POSTGRES_PASSWORD. Never commit .env or real secrets.

2. Configure PACA_JWT_ISSUER, PACA_JWT_AUDIENCE, and PACA_JWT_JWKS_URL for a real test identity provider. The example identity.example.org values are placeholders and will not authenticate real users.

3. Review the OPA policy and ensure PACA_EXPECTED_POLICY_REVISION matches production_service/opa/data.json.

4. Start the stack:

   ~~~sh
   docker compose up --build --wait
   ~~~

5. Check liveness:

   ~~~sh
   curl --fail http://127.0.0.1:8000/healthz
   curl --fail http://127.0.0.1:8000/readyz
   ~~~

6. Stop the stack:

   ~~~sh
   docker compose down
   ~~~

The API binds to loopback on port 8000 in the supplied Compose file. Do not expose it externally until TLS, ingress authentication/rate limits, secrets, database roles, network rules, backup/restore, retention, monitoring, and incident response have been configured and tested.

## Python tests

From this directory:

~~~sh
python -m pip install -e ".[dev]"
pytest -q
ruff check .
~~~

The PostgreSQL integration tests require a reachable test database and the relevant test environment variable; consult the test module and CI workflow for the exact setup. A test pass covers only the exercised cases.

## Important limitations

- The example Compose configuration is for local evaluation. Do not reuse its database role/password pattern for a production deployment.
- The issuer, audience, JWKS endpoint, policy revision, and optional downstream routes must be configured to match the actual deployment.
- Remote side effects cannot be atomically committed with this service's PostgreSQL transaction. Ambiguous outcomes require downstream idempotency or operator reconciliation; do not blindly retry.
- The database audit trigger is not immutable against a database administrator or superuser. Export events to independently controlled, retention-protected storage.
- Passing CI is not a penetration test, formal verification, external audit, or guarantee of safe behavior under all interleavings.

See the threat model in THREAT_MODEL.md for trust boundaries and residual risks.
