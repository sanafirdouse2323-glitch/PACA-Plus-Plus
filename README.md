# PACA++ — authorization research prototype and production-service scaffold

PACA++ is an early research project exploring authorization correctness at the LLM-agent execution boundary. The repository's original ALFA/UCON+ to ASP/Cedar compiler goal is **not implemented by the current prototype**, and this branch does not claim otherwise.

## Repository layout

- `prototype/` contains a small Python research engine, deterministic toy scenarios, and tests. It performs simulated effects only.
- `production_service/` contains the separately packaged HTTP service integrating OPA/Rego, issuer-verified RS256 JWTs, PostgreSQL-backed permits and executions, context retrieval from protected resource records, durable append-only audit events, idempotency tracking, status/recovery handling, and protected tool/API adapters.
- `.github/workflows/production-service.yml` runs Python tests against PostgreSQL and tests the Rego policy with the pinned OPA image.

## Run the research prototype

Requires Python 3.10 or newer:

```bash
cd prototype
python -m unittest discover -s tests -v
python examples/demo.py
python experiments/run_experiments.py
python examples/authorize.py --policy examples/policy.json --context examples/context.json --action file.read --resource file:report-1 --principal-id demo-user --execute
```

The demo and CLI perform only simulated effects. They do not call real tools or APIs.

## Production-service scaffold

Start with [the production-service deployment guide](production_service/README.md) and [the security/threat model](production_service/THREAT_MODEL.md). The service requires your actual OIDC issuer/JWKS endpoint and trusted token claims; it deliberately has no insecure "development token" bypass.

This is a **production-oriented implementation baseline, not a production-approved or certified security product**. Do not expose it directly to the public internet or use sensitive workloads until the deployment-specific security gates in the guide have passed.

## What the implementation does not prove

The deterministic examples do not prove security under every interleaving or on every downstream system. PostgreSQL coordinates this service's permit and idempotency state, but it cannot create an atomic transaction with an arbitrary external API. On ambiguous external outcomes, the service records `unknown` and does not automatically retry. The downstream service must support its own idempotency or reconciliation contract, and any changing authorization facts owned by that downstream system must be revalidated there.

The append-only audit trigger is a defense-in-depth measure, not tamper-proof storage against database administrators or superusers. Production deployments should use a dedicated least-privilege runtime database role and export audit data to separately controlled, retention-protected storage. A passing CI run is useful evidence, but not a penetration test, formal proof, independent security audit, standards certification, or proof of research novelty.
