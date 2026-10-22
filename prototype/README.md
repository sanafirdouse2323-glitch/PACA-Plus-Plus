# PACA++ Research Prototype MVP

This is a runnable research prototype kept separate from the repository's original ALFA/UCON+ goal. It currently uses a small JSON policy format; it does **not** yet parse or compile ALFA/UCON+ policies or invoke real external tools.

## Requirements
- Python 3.10 or newer
- No third-party runtime dependencies for direct execution

## Run from this directory

```bash
python -m unittest discover -s tests -v
python examples/demo.py
python experiments/run_experiments.py
python examples/authorize.py --policy examples/policy.json --context examples/context.json --action file.read --resource file:report-1 --execute
```

The final command evaluates the JSON policy and, when permitted, performs only a **simulated** effect. It never reads a real file or calls an external tool.

To try a denied action, change `--action file.read` to `--action file.delete`. The CLI prints a JSON decision and does not execute the simulated effect after denial.

## Implemented safeguards
- Default deny when no permit rule matches.
- Missing attributes fail closed, including `ne`.
- Exact action and resource binding at effect time.
- Deny-overrides policy combination.
- Short-lived, one-use permits.
- Policy/state version revalidation.
- A local lock around permit validation and the effect callback.
- Tests for substitution, replay, stale state/policy, namespace confusion, and concurrent replay.

## Limitations
This is a research scaffold, not a production authorization service. It uses an in-memory, process-local permit store and assumes trusted identity/context and stable resource identifiers. The local lock does not provide distributed transactions or undo a remote side effect. There is no production identity provider, durable tamper-resistant audit, complete ALFA/UCON+ DSL, real ASP/Cedar backend, external tool adapter, formal proof, or independently validated novelty claim.

See [the design specification](docs/PACA_Prototype_Full_Design.md), [threat model](THREAT_MODEL.md), and [local verification report](docs/LOCAL_VERIFICATION_REPORT.md).
