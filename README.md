# PACA++ — authorization research prototype

PACA++ is an early research project exploring authorization correctness at the LLM-agent execution boundary. The repository's original ALFA/UCON+ to ASP/Cedar compiler goal is **not implemented by the current prototype**, and this branch does not claim otherwise.

## What this branch adds

The `prototype/` directory now contains two layers:

- A small, dependency-free research engine for deterministic authorization tests.
- A production-oriented integration layer with OPA/Rego, verified OIDC/JWT identity, server-side authorization-context interfaces, a protected HTTP operation API, fixed-destination downstream HTTP adapter, durable SQLite/PostgreSQL operation stores, idempotency handling, unknown-outcome recovery, and a hash-chained audit log.

The integration layer remains incomplete for any particular deployment until a real application-specific context provider, identity-provider configuration, downstream tool service, and operational controls are implemented and reviewed. See [the production deployment guide](prototype/docs/PRODUCTION_DEPLOYMENT.md) and [phase-one hardening notes](prototype/docs/PRODUCTION_HARDENING_PHASE_1.md).

## Run the local test suite

Requires Python 3.11 or newer:

```bash
cd prototype
python -m unittest discover -s tests -v
python examples/demo.py
python experiments/run_experiments.py
python examples/authorize.py --policy examples/policy.json --context examples/context.json --action file.read --resource file:report-1 --principal-id demo-user --execute
```

The demo and command-line example perform only simulated effects. To run live OPA and PostgreSQL integration tests, install the production extras and follow the [deployment guide](prototype/docs/PRODUCTION_DEPLOYMENT.md). GitHub Actions in this branch is configured to validate Rego, start OPA and PostgreSQL, and execute the integration suite. A configured workflow is not evidence of a passing run; check the recorded workflow status.

## Security properties and limitations

The integration is designed to deny by default, verify the caller token, retrieve authorization attributes from trusted server-side readers, ask OPA for a decision, re-check context immediately before dispatch, and atomically claim a durable idempotency record before invoking a registered handler.

It cannot promise exactly-once execution of an arbitrary remote side effect. When an operation's outcome is ambiguous, it records an unknown result and requires reconciliation from the downstream system's authoritative evidence. A hash chain is tamper-evident, not tamper-proof. A policy update can still race with an external action after the last policy evaluation unless the enforcement boundary shares an appropriate transactional or versioned-policy mechanism.

The test scenarios are not a formal proof, external benchmark, independent penetration test, standards certification, or proof of research novelty.
