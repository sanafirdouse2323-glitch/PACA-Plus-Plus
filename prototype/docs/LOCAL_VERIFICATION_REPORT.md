# Local verification report

## What was run locally

The matching development package was exercised before the prototype files were uploaded:

- Unit tests: 12 passed.
- Demo: ran and showed a successful simulated read, action-substitution rejection, and missing-attribute denial.
- Deterministic scenario runner: 10 scenarios; 10/10 expected authorization decisions and 10/10 expected effect outcomes matched.

## Important reproducibility note

The report above records the local development-package run, not a verified GitHub Actions run for the exact merged commit. At the time this file was updated, the connected GitHub integration returned no workflow-run records or commit status checks for the merged revision. Therefore, do not interpret this as confirmation that CI has passed on GitHub.

To verify the exact checkout, run from the repository root:

```bash
cd prototype
python -m unittest discover -s tests -v
python examples/demo.py
python experiments/run_experiments.py
```

## Limits

These are deterministic, hand-authored toy tests, not an independent security audit, an external-system benchmark, a formal proof, production-security evidence, standards-compliance evidence, or proof of research novelty. The local in-memory permit store is process-local; trusted identity/context and stable resource identifiers are assumptions.