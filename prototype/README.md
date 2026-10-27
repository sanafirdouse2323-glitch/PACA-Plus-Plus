# PACA++ Research Prototype

The repository keeps its original ALFA/UCON+ compiler goal distinct from its Python research prototypes. The checked-in Python package currently does not parse or compile ALFA/UCON+ policies.

## Requirements

- Python 3.10 or newer.
- PyJWT with cryptography support is installed by the project package for configured RS256/OIDC verification.
- Docker is needed only for the real OPA policy smoke test.

## Run from this directory

~~~bash
python -m pip install -e ".[web,test]"
python -m unittest discover -s tests -v
python examples/demo.py
python experiments/run_experiments.py
docker compose up -d opa
docker compose --profile integration up -d postgres
python examples/opa_smoke.py
# Use real deployment credentials in .env, then run:
# uvicorn paca_mvp.service:create_app --factory --host 127.0.0.1 --port 8080
docker compose down
~~~

The old **AuthorizationEngine** still uses a process-local permit store and its demo runs only a simulated effect. The separate hardening path adds **OPAClient**, **OIDCJWTIdentityProvider**, **HTTPAuthorizationContextProvider**, **SQLitePermitStore**, multi-host **PostgresPermitStore**, **GuardedGateway**, protected tool/API adapters, a runnable ASGI gateway at `paca_mvp.service`, and an optional reference context service at `paca_mvp.context_service`. The context service resolves roles, current suspension, capabilities, internal principal IDs, and resource ownership from administrator-managed PostgreSQL data. Audit events and export intents are committed together, and `paca-audit-export` delivers them at least once through a leased retryable outbox to a configured HTTPS sink. The receiver must durably deduplicate events and enforce independent append-only/WORM retention; no real receiver is provisioned by this repo. See [the hardening guide](docs/SECURITY_HARDENING.md) for setup and limitations. LLM applications should also pass every model-proposed tool call through the [agent attack boundary](docs/AGENT_ATTACKS.md) and [retrieval/output content boundaries](docs/CONTENT_BOUNDARIES.md), including the `GuardedAgentPipeline` facade for retrieval, tool calls, and final-output release, plus the [inter-agent message boundary](docs/INTER_AGENT_BOUNDARY.md) for authenticated-route checks and untrusted-message taint. See the [threat coverage and evidence matrix](docs/THREAT_COVERAGE.md) for tested properties, partial mitigations and unimplemented gaps. These controls reduce specific attack paths but do not claim to defeat every prompt injection.

## Security boundaries

- OPA decision failures, missing or malformed permit results, and missing active policy versions must fail closed.
- The OIDC adapter verifies RS256 signatures and issuer/audience/expiry claims against a configured HTTPS JWKS endpoint. A real identity provider, suitable claims, and revocation/tenant policy remain deployment responsibilities.
- The trusted context provider must be an administrator-configured service. The reference implementation maps issuer/subject/audience to an internal principal within the registered resource tenant; ownership checks compare internal IDs and tenant IDs, not raw OIDC subjects. Caller-supplied identity and role claims are not authorization context.
- SQLite transactions coordinate processes sharing one local database file; use `PostgresPermitStore` (included) for multi-host coordination.
- Durable permits and idempotency records prevent automatic replay. A crash during a remote effect results in an **unknown** operation requiring downstream reconciliation; local SQLite and an arbitrary remote service do not share an atomic transaction.
- **verify_audit_chain()** detects modified events, broken links, and tail truncation when the separately stored head is unchanged; it is not tamper-proof against an attacker who can rewrite the database and head. The transactional outbox preserves export intent and retries failed exports, but delivery is at least once; the independent receiver must deduplicate by event ID/hash and enforce append-only/WORM retention.
- The HTTP adapter requires preconfigured routes and HTTPS and sends a downstream idempotency key. It cannot force the remote API to honor that key.
- The filesystem adapter confines access to admin-configured logical resources under a configured root and uses POSIX no-follow path traversal. Run it with least privilege and do not expose it to untrusted callers without the gateway.
- The sample Rego policy (version `paca-example-v4`) uses internal-principal and tenant-bound analyst reads plus support ticket creation gated by a trusted capability. Permits require `suspended=false` from the trusted authorization context; a signed JWT `suspended=true` claim also denies. Missing current suspension status defaults to deny. The policy is illustrative, and its version marker must be incremented as policy changes. Production deployments should use verified policy bundles/revisions, secure OPA, and coordinate policy rollout with effects.

These components are a hardening foundation—not a production-readiness claim, independent security audit, formal proof, standards-compliance claim, or proof of research novelty.
