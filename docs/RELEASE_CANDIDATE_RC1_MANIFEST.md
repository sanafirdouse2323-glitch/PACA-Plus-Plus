# PACA++ external assessment release candidate 1

**Status:** pinned candidate for independent technical assessment; not a production-release approval, certification, or security assurance claim.

**Prepared:** 19 November 2026

## Repository and source boundary

- Repository: `sanafirdouse2323-glitch/PACA-Plus-Plus`
- Candidate branch: `assessment/paca-plus-plus-rc1-2026-11-19`
- Source baseline: `main` at `bdf660aa6dfd022df717037c723be5a2221eabe0`
- Candidate construction: this branch is based on that exact `main` commit. This manifest is the only intended addition to the source tree for RC1. The commit containing this manifest is the assessment candidate; the statement of work must identify its full commit SHA, not rely on the branch name.
- Repository boundary: assess this repository only. Do not use, import, or claim results from `PACA-Plus-Plus-New`.

## Included scope

Assess the code and configuration actually present at the pinned candidate commit, including:

- `production_service/`: FastAPI authorization/execution gateway, OIDC/JWT validation, OPA integration, permit/execution state, PostgreSQL/RLS controls, configured adapters and deployment files;
- `prototype/`: research agent runtime and boundary modules, with separately identified limitations and host integration assumptions;
- `agent/`: the checked-in LangGraph adapter and its actual configured persistence/test coverage;
- the compiler and policy material present at this commit, only to the extent the assessor's agreed scope includes those components.

The assessor must verify the implementation and deployed test environment directly. The component list is a scope index, not a claim that every item has been independently verified or that every adapter is enabled by default.

## Explicit exclusions and known version boundaries

- PR #33's browser demo console is open and unmerged; it is **not** part of this candidate and must not be treated as assessed.
- PR #34's architecture/README/CI-trigger documentation corrections are open and unmerged; the assessor should use the separately supplied assessment scope and verify claims against the code at this SHA rather than assume those proposed documentation edits are present.
- PR #35's assessment/benchmark plan is open and unmerged; its frozen protocol is separately pinned at commit `b0e6f8f683fe4b32c7ac92f11994ac5eba783559` on branch `benchmark/paca-protocol-v1.0.0-frozen`. That protocol commit is a separate planning artifact, not part of the RC1 source tree.
- No code or evidence from `PACA-Plus-Plus-New` is in scope.
- No production deployment, customer data, signing keys, production credentials, or unrestricted production access are authorized by this manifest.

## Assessment operating conditions

Use a disposable isolated environment, synthetic tenants/resources/identities, test-only credentials and non-production keys. Agree written rules of engagement and allowed test windows with the external assessor before testing. Record the exact environment, images, dependency resolution, enabled adapters, configuration, tests performed, tests not performed, exclusions and any deviations.

Do not modify this candidate during assessment. Findings that require remediation must be addressed on a new commit and assessed as a new candidate or retest target. Preserve the original SHA and report against it.

## Benchmark gate

No confirmatory comparative benchmark results are authorized by this manifest alone. Before benchmark data collection, commit and pin a completed preregistration manifest as required by the separately frozen protocol. It must include the exact candidate SHA, harness and baseline SHAs, policy/configuration hashes, scenario matrix, outcome oracle, environment/image digests, primary endpoint, trial counts and power assumptions, statistical methods, exclusions and stopping rule. Calibration runs must be identified as non-evaluative and excluded from confirmatory results.

## Interpretation

This is a reproducible source snapshot for independent assessment. It does not establish production readiness, effectiveness, complete mediation of host effects, resistance to all prompt injection, formal verification, certification, or superiority over other products.
