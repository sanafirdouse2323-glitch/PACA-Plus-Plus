# PACA++ Research Prototype MVP

This prototype is kept in a separate prototype/ directory so it does not overwrite the existing PACA++ implementation.

## What it demonstrates
- Default-deny authorization decisions.
- Exact action/resource binding between authorization and protected effect.
- Missing attributes fail closed, including for ne comparisons.
- Deny-overrides policy combination.
- Short-lived, one-use permits.
- Policy/state version checks before an effect.
- A deterministic adversarial scenario runner.

## Run (Python 3.10+)

```bash
cd prototype
python -m unittest discover -s tests -v
python examples/demo.py
python experiments/run_experiments.py
```

No third-party runtime dependencies are required.

## Limitations
This is a research scaffold, not a production security product. It uses an in-memory, process-local permit store; trusted identity/context and canonical resource identifiers are assumptions. It does not provide distributed transactions, durable tamper-resistant audit, a complete policy DSL, formal proof, or an external tool executor. Scenario results are deterministic toy-test results, not a benchmark or proof of security, standards compliance, or novelty.

See docs/PACA_Prototype_Full_Design.md and THREAT_MODEL.md.