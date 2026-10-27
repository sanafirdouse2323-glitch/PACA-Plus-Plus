# PACA++ content boundaries: retrieval, output, and trust

## Why this layer exists

The incident review identifies two gaps a tool-call gate alone does not cover: retrieval-phase provenance filtering and output-formatting exfiltration. This module adds deterministic enforcement at those boundaries without duplicating the existing authorization, OPA, durable-permit, or tool-routing checks.

## Request path

1. **Ingestion:** a trusted application component assigns each document a source identifier and trust label: `trusted`, `internal`, `untrusted`, or `unknown`. Never derive trust from the document's own claims or model-generated metadata.
2. **Retrieval gate:** call `filter_retrieval` after candidate retrieval and before content enters model context. The default admits only `trusted` and `internal`. Other items are excluded with a reason code. A use case may explicitly allow untrusted content as data, but must retain its label and never promote its authority.
3. **Agent reasoning:** labels are context, not authorization. The model may still be influenced by injected instructions. Every proposed effect must go through the existing `AgentToolBoundary` and `GuardedGateway`.
4. **Output gate:** call `OutputBoundary.inspect` after generation and before returning content to a UI, sending a message, or invoking a renderer. Deliver only when `allowed=True`. If denied, do not deliver or render the original output; return a fixed safe error or regenerate under a constrained policy.

## Implemented checks

- Denies remote Markdown image beacons.
- Denies raw HTML active elements (including image, iframe, script, SVG, form and embedded media), including data-URI and event-handler variants.
- Denies HTTP(S) links unless their host is explicitly allowlisted.
- Denies common credential patterns and configured sensitive values.
- Checks output type, Unicode validity and size.
- Enforces retrieval provenance and document/character budgets.

## Limits that must remain explicit

- This is not a universal prompt-injection detector and does not reliably detect every secret, PII item, encoded payload, steganographic channel or covert channel.
- The host allowlist must be administrator-controlled. An allowed host can still leak data through query parameters; only allow hosts that are safe to receive the output.
- This checks output text, not every downstream client's behavior. Clients need restrictive rendering, disabled raw HTML/remote images, CSP and network-egress policy as appropriate.
- Provenance is only as reliable as trusted ingestion. If an LLM can set `trust="trusted"`, this gate is bypassed by design.
- Default retrieval filtering can reduce recall. Where untrusted sources are needed, retain their labels and enforce effects out-of-band.
- This does not prevent platform bugs, compromised dependencies, direct calls to separately exposed endpoints, or unsafe executor code. Use sandboxing, least privilege and ordinary application security controls.
- Planning/SMT verification remains a separate hypothesis. No solver or formal proof is implemented here.
- Inter-agent messages should be untrusted unless sender identity and delegated capabilities are independently authenticated. This module is not a complete multi-agent protocol.

## Minimal integration pattern

```python
from paca_mvp.content_boundary import OutputBoundary, filter_retrieval

retrieval = filter_retrieval(candidate_documents)  # provenance assigned by trusted ingestion
model_context = [
    {"source": d.source, "trust": d.trust, "content": d.content}
    for d in retrieval.included
]

decision = OutputBoundary(
    allowed_link_hosts=("docs.example.org",),  # administrator-controlled
    sensitive_values=(known_secret_or_sensitive_value,),
).inspect(model_output)
if not decision.allowed:
    return {"error": "output_blocked", "reasons": list(decision.reason_codes)}
return {"text": decision.text}
```

The example host and sensitive value are placeholders. Do not log raw blocked output by default because it may contain the secret that triggered the block.

## Validation

Run from `prototype/`:

```bash
python -m unittest discover -s tests -v
```
