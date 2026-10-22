# PACA++ — research prototype

This repository is an early research scaffold for exploring authorization correctness in LLM-agent systems. The existing root-level description refers to compiling ALFA/UCON+ policies to ASP and Cedar; that compiler integration is **not implemented by the new prototype yet**.

## Current runnable component

The isolated [prototype](prototype/README.md) directory contains a Python research MVP for testing the authorization-to-effect boundary:

- default-deny decisions and deny-overrides;
- fail-closed handling of missing attributes;
- permits bound to an exact action, resource, policy version, and state version;
- short-lived, one-use permits and replay rejection;
- a simulated protected effect, audit events, unit tests, deterministic scenarios, and a command-line interface.

The prototype is intentionally separate so it does not silently replace or misrepresent the original ALFA/UCON+ compiler work.

## Run it

Requires Python 3.10 or newer. No third-party runtime dependencies are required.

From a clone of this repository:

```bash
cd prototype
python -m unittest discover -s tests -v
python examples/demo.py
python experiments/run_experiments.py
python examples/authorize.py --policy examples/policy.json --context examples/context.json --action file.read --resource file:report-1 --execute
```

GitHub Actions runs these checks for pushes to the prototype branch and pull requests targeting `main`.

## What the results mean

The included scenario suite is a small, hand-authored test set. Passing it only shows that the current implementation behaves as expected for those cases; it is not a formal proof, an external-system benchmark, production-security validation, standards compliance, or proof of research novelty.

## Important remaining work

1. Integrate and test the original ALFA/UCON+ policy syntax, parser, compiler, and evaluator (rather than claiming the MVP already does this).
2. Add differential tests for parser/compiler/evaluator semantic consistency.
3. Add independently reviewed adversarial cases and compare supported features against relevant existing systems.
4. Define tool-specific canonicalization, trusted identity/context, durable audit, and deployment assumptions before considering real side effects.
5. Decide the final research contribution only after the baseline and literature comparisons.

See [the design specification](prototype/docs/PACA_Prototype_Full_Design.md), [threat model](prototype/THREAT_MODEL.md), and [local verification report](prototype/docs/LOCAL_VERIFICATION_REPORT.md).
