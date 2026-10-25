# PACA++ production-service scaffold

This directory contains a separate FastAPI authorization gateway that combines RS256 JWT verification, resource-context lookup, OPA/Rego policy decisions, PostgreSQL-backed permits and execution state, and configured file/tool/API adapters.

**Status:** controlled-evaluation scaffold. It is not production-certified and the setup instructions are not a substitute for a deployment-specific security review.

## Fresh local setup

1. Copy `.env.example` to `.env`. Generate two independent secrets with `openssl rand -hex 32`; put one in `POSTGRES_PASSWORD` and the other in `PACA_RUNTIME_PASSWORD`. PostgreSQL's bootstrap/admin account uses the first; the API uses a restricted `paca_runtime` account.
2. Set `PACA_JWT_ISSUER`, `PACA_JWT_AUDIENCE`, and `PACA_JWT_JWKS_URL` to your actual test identity provider. The example `identity.example.org` settings are placeholders.
3. Ensure the policy revision equals `production_service/opa/data.json`. In this service, `protected_resources.owner_id` is compared with the verified OIDC `sub`; provision the owner value accordingly, and only trust role/scope/tool claims from an issuer that controls them.
4. For a newly initialized local database volume, start the stack:

   ```sh
   docker compose up --build --wait
   ```

5. Check both endpoints:

   ```sh
   curl --fail http://127.0.0.1:8000/healthz
   curl --fail http://127.0.0.1:8000/readyz
   ```

   `/healthz` only indicates that the process is alive. `/readyz` verifies database connectivity and a real OPA deny-by-default decision that must carry the configured policy revision.

The API binds to loopback on port 8000. Do not expose it externally before configuring and validating TLS ingress, rate/request limits, secrets management, egress controls, backups/restore, audit retention, monitoring, and incident response.

## Upgrading an existing volume safely

The official PostgreSQL image runs `/docker-entrypoint-initdb.d/` scripts only when initializing an **empty** data directory. Editing `.env` and restarting does not create `paca_runtime` or reapply grants to an existing volume.

Before upgrading, take and verify a database backup. Keep the existing data volume. With the old database administrator still available, update `.env` with a strong `PACA_RUNTIME_PASSWORD`, then run these commands from `production_service/`:

```sh
docker compose exec database bash -lc 'source /docker-entrypoint-initdb.d/000-runtime-role.sh'
docker compose exec -T database psql -U paca -d paca -v ON_ERROR_STOP=1 -f /docker-entrypoint-initdb.d/002-runtime-grants.sql
docker compose up --build -d
```

The role-creation script is idempotent so it can be rerun for a controlled upgrade. The second command reapplies the grants. If the old database administrator credential is unavailable, stop and recover access before changing roles. **Do not run `docker compose down -v`** to solve a permission error: that deletes persistent volumes.

## Test and lint

From this directory:

```sh
python -m pip install -e ".[dev]"
pytest -q
ruff check .
```

PostgreSQL integration tests need both `PACA_TEST_DATABASE_URL` (restricted runtime role) and `PACA_TEST_ADMIN_DATABASE_URL` (fixture/schema administration). If either is missing, those tests are skipped; skipped tests are not passing database tests.

## Residual limits

- Compose is for local evaluation, not a production deployment recipe.
- Remote PostgreSQL must use `sslmode=verify-full`; remote OPA and downstream HTTP endpoints must use HTTPS.
- The runtime role cannot provision or alter trusted resource facts. An administrator-controlled process must provision them.
- PostgreSQL cannot atomically commit an arbitrary external API effect. On ambiguous outcomes, the service records `unknown` and does not blindly retry; downstream idempotency/reconciliation remains required.
- An in-database append-only trigger is not immutable against an owner or superuser. Export audit events to independently controlled retention-protected storage.
- Passing CI is not a penetration test, formal proof, independent audit, external benchmark, standards-compliance claim, or proof of research novelty.

See [THREAT_MODEL.md](THREAT_MODEL.md) for trust boundaries and deployment gates.
