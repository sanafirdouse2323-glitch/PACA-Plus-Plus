# Threat coverage and evidence tiers

## How to read this matrix

The incident review recommends separating claims into **Strong**, **Plausible**, and **Aspirational** rather than treating all mechanisms as equally effective. This matrix applies that discipline to the code currently in this repository.

The tier describes the evidence for a **specific prototype property**, not a blanket guarantee that an entire real-world incident is prevented. Passing automated tests shows that tested cases behave as expected; it is not a formal proof, a production security audit, or an exhaustive attack evaluation. No incident-prevention count is claimed from the tests alone.

## Current coverage

| Threat area | Implemented mechanism | Evidence and confidence | Boundary / remaining gap |
|---|---|---|---|
| Model-proposed tool calls and unauthorized effects | Static tool allowlist, fixed action/resource routing, strict argument validation, budgets, request/call-ID binding, optional approval verification, untrusted tool-result labels; protected effects can be routed through GuardedGateway, OPA and durable permits. | **Strong for the specific tested boundary properties.** Adversarial tests exercise unknown tools and fields, invalid values, approval binding, replay/rebinding and guarded gateway behavior. | Protection depends on every sensitive effect being reachable only through the guarded path. An exposed downstream endpoint, unsafe executor, compromised dependency, or platform vulnerability is not fixed by this boundary. |
| Retrieval provenance and trust downgrade | HMAC binds document ID, source, source-policy-derived trust level and content digest. Administrator-configured source mapping sets trust; unknown sources are not trusted by default. Retrieval filtering enforces trust and size budgets. | **Strong for the tested integrity and allowlist checks.** Tests cover source trust, tampering and retrieval budgets. | HMAC proves integrity/issuer-key possession, not that content is true or free of prompt injection. Key custody and trusted ingestion remain critical. |
| Output-formatting exfiltration | Final-output gate rejects Markdown image syntax, raw HTML, unsafe or non-allowlisted links, common credential patterns, configured sensitive values and oversized/non-text output. | **Plausible partial mitigation.** Deterministic regression tests cover the implemented patterns, including image beacons and unsafe links. | This is not comprehensive DLP or a universal exfiltration detector. Unknown encodings, covert channels, sensitive values not configured, authorized-host abuse, and downstream renderer/network behavior require additional controls. |
| Inter-agent message ingress | Configured sender-to-recipient routes; sender identity supplied by independently authenticated host transport; exact envelope; size and attempt budgets; per-instance replay rejection; all accepted messages are labeled untrusted. | **Plausible partial mitigation** for route spoofing, envelope abuse and repeated-message cases under the documented integration contract. | The module does not authenticate the transport itself, persist replay state across processes, delegate permissions, or semantically detect prompt injection in agent-authored text. |
| Image/audio/video and other multimodal prompt injection | No image-pixel inspection, OCR, audio/video analysis, or multimodal classifier is implemented in this prototype. | **Aspirational / not implemented.** | Text provenance and output checks do not establish that a multimodal input is safe. A separate multimodal inspection and evaluation path is needed. |
| Compositional planning attacks / whole-plan verification | No whole-plan SMT solver or formal plan verifier is implemented here. | **Aspirational research hypothesis / not implemented.** | The code does not prove that individually allowed actions cannot compose into a disallowed campaign. Solver expressiveness, scale and false-positive rate would need a separate implementation and evaluation. |
| Platform, dependency, credential and downstream-service vulnerabilities | Ordinary integration and infrastructure hardening exists in parts of the repository, but these agent-boundary modules do not repair arbitrary platform vulnerabilities. | **Outside the agent-boundary claim.** | RCEs, exposed credentials, vulnerable dependencies, unsafe rendering, open redirects, CORS mistakes and direct endpoint compromise require platform, dependency, identity, network and operational controls. |

## Required integration invariants

1. **Every effect** must pass through the configured tool boundary and protected gateway. No alternate executor or directly reachable downstream route may bypass the policy path.
2. **Retrieved and inter-agent content remains data**, not authorization, policy, a capability grant, or human approval. Trust labels do not make semantic content safe.
3. **Only release approved output.** The caller must deliver the string returned by the output boundary and must never render the rejected original. Use restrictive rendering, CSP and network-egress controls where applicable.
4. **Keep trust configuration outside model control.** The model must not assign document trust, authenticated sender identity, allowed routes, approval state, or tool action/resource mappings.
5. **Test the deployed composition.** Unit tests do not establish that a host application invokes each boundary on every path. End-to-end integration tests and independent security review are still required.

## Reproducible validation

From the prototype directory:

~~~bash
python -m unittest discover -s tests -v
~~~

The CI workflows also exercise the prototype suite, compiler regressions, OPA policy, and service/PostgreSQL integration. Their status should be checked for the exact commit being released; a prior successful run does not validate later changes.
