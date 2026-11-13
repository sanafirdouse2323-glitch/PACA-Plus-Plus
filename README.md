# PACA++ — policy and access control for agent-based systems

I am developing PACA++ to address a practical security problem: when an application or an agent tries to use a tool, access a record, or carry out an operation, how do we make sure that the action is still allowed at the point where it happens?

A permission check at the beginning of a request is not always enough. The user, resource, policy, or execution context may change before the operation is completed. PACA++ explores ways to keep the authorisation decision tied to the action, the resource, and the context in which the action is carried out.

This repository contains several related pieces of work. They are at different stages and should not be treated as one finished product.

## What is included

- **`production_service/`** — a FastAPI service that checks an OIDC access token, asks OPA/Rego for an authorisation decision, looks up trusted resource information, and records permits and execution state in PostgreSQL. It includes configured file, tool, and API adapters. PostgreSQL row-level security protects tenant-scoped records. The tenant context is signed by the API and checked by PostgreSQL before access is allowed.
- **`prototype/`** — an earlier in-memory policy engine and a separate hardened prototype. The hardened path includes OPA, OIDC/JWKS verification, trusted authorisation context, database coordination, execution recovery, adapters, and an audit outbox. The in-memory demo uses simulated effects; it is not the same service as the production-service scaffold.
- **`compiler/` and root `tests/`** — an experimental parser and text emitters for a limited policy subset, with regression tests for the syntax currently supported.
- **`legacy_policy_engine/`** — a copy of the earlier policy-engine source, kept separately so that its files do not overwrite the newer prototype or service. It is not yet part of the root CI checks and needs its own validation before I treat it as a supported package.
- **`archive/paca-plus-plus-new/`** — historical material from the earlier repository. It is kept for reference and is not an importable working package.

The compiler, prototype, and production service have different purposes and different levels of testing. Please check the README and threat model inside the relevant directory before running or evaluating one of them.

## What the current service is intended to protect

The production-service scaffold combines several checks rather than relying on one permission check alone:

1. The API verifies an access token against a configured OIDC issuer, audience, and JWKS endpoint.
2. OPA/Rego evaluates the request against the policy and the trusted resource information supplied to the service.
3. PostgreSQL stores permits and execution records and applies row-level security to tenant-scoped tables.
4. Before a tenant-scoped database operation, the API signs a short-lived context containing the tenant, verified principal, database backend and transaction details, timestamps, and key ID.
5. PostgreSQL verifies that signature using a key stored in a private schema that the runtime database role cannot read.

This is intended to stop a database session from gaining access to another tenant's rows simply by changing a session setting. The signed context is tied to the current database backend and transaction, so a captured context cannot simply be reused in another transaction.

This does not mean every action by an agent is safe. The current database controls do not, on their own, stop every form of prompt injection, memory poisoning, unsafe tool call, data disclosure, or unauthorised external communication. OPA and the application still need to enforce principal and resource permissions within a tenant.

## Run the compiler tests

From the repository root:

```bash
python -m pip install lark-parser
PYTHONPATH=. python -m unittest discover -s tests -p "test_fuzzer.py" -v
```

The compiler currently handles only a limited policy subset. The tests check the supported parsing and generated-text behaviour. They do not show that the compiler supports the full ALFA or UCON+ specifications, or that its ASP and Cedar outputs are semantically equivalent.

## Run the research prototype

From `prototype/`:

```bash
python -m pip install -e ".[web,test]"
python -m unittest discover -s tests -v
python examples/demo.py
python experiments/run_experiments.py
```

The demo uses simulated effects. The experiment scenarios are a small set of hand-written cases, not an independent benchmark. Their results should not be presented as proof that PACA++ is better than another system.

## Run the production-service scaffold

Start with the [production-service setup guide](production_service/README.md) and read its [threat model](production_service/THREAT_MODEL.md).

The service needs a real test OIDC issuer and JWKS endpoint, correctly provisioned resource information, OPA policies, PostgreSQL credentials, and a private tenant-context signing key. The example identity-provider values and example HMAC key in the repository are not deployment credentials. Replace them before running the service outside an isolated local test.

For local evaluation, follow the setup and migration instructions in `production_service/README.md`. In particular, back up an existing database before applying the upgrade steps. Restarting a database container does not apply the initialisation scripts to an existing data volume.

## What has been tested

The repository's CI has passed the configured checks for the merged implementation, including the production-service tests, a live Keycloak OIDC integration test, OPA policy checks, PostgreSQL tenant-isolation and upgrade checks, and the compiler regression workflow.

That is useful evidence that the tested paths work. It is not a claim that every possible attack has been covered. It is also not an independent security audit, penetration test, formal proof, external benchmark, or production certification.

I have not yet established that PACA++ outperforms existing access-control or agent-security systems. That needs a fair comparison using the same tasks, attacks, and measurements for each system. Useful measures include attack success, completion of legitimate tasks, false denials, latency, and recovery behaviour.

## Known limits and work still needed

- The production service is a controlled-evaluation scaffold, not a production-certified service.
- The API process and its signing key must be protected. A compromise of the API host, signing key, database owner, or database superuser is outside the protection provided by the signed tenant context.
- Row-level security provides tenant-level separation. It does not replace checks for which individual user may access a particular resource.
- PostgreSQL cannot make an arbitrary remote API operation part of the same transaction. If the outcome of an external operation is unclear, the service records an unknown state rather than blindly retrying it. The downstream system still needs idempotency and a way to reconcile the result.
- Global stale-execution recovery is an administrator-only operation. It marks qualifying executions and permits as unknown; it does not retry the external operation. Operators must investigate and choose a suitable age threshold before running it.
- An audit table or trigger inside the same database is not protected against a database owner or superuser changing the records. Important audit records should also be exported to separately controlled storage.
- A real deployment needs a reviewed migration, tested backup and restore, secure secret storage, TLS, network and egress controls, monitoring, audit retention, incident response, and tests against the actual downstream services.
- The compiler needs broader language coverage and semantic checks. The legacy package needs independent validation.
- The wider agent-security claims need dedicated tests for prompt injection, unsafe tool use, memory-based attacks, data disclosure, and attempts to bypass authorisation.

## Current status

PACA++ is an ongoing engineering and research project. The repository contains working components and passing tests, but the different parts are not equally mature. My next priority is to test the security boundaries against realistic attack scenarios, measure the effect on normal task completion, and compare the results with existing approaches before making claims about effectiveness.

The aim is to make the permissions that an application grants clear, checkable, and enforceable when an operation is actually carried out—not just when a request first arrives.
