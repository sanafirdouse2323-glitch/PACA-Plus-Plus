# PACA++ content boundaries: retrieval, output, and trust

## Why this layer exists

The incident review identifies two gaps a tool-call gate alone does not cover: retrieval-phase provenance filtering and output-formatting exfiltration. This module adds deterministic enforcement at those boundaries without duplicating the existing authorization, OPA, durable-permit, or tool-routing checks.

## Request path

1. **Ingestion:** a trusted component assigns each document a source identifier and trust label: `trusted`, `internal`, `untrusted`, or `unknown`. It issues provenance using `ProvenanceAuthority.issue`; an HMAC signature binds the document ID, source, trust label and content digest. Never derive trust from the document's own claims or model-generated metadata. Keep the HMAC key only in trusted ingestion/retrieval code; never expose it to an LLM, plugin or tool output. For separate ingestion and retrieval services, use an asymmetric signing service instead of distributing the HMAC secret.
2. **Retrieval gate:** call `filter_retrieval` after candidate retrieval and before content enters model context. The default admits only `trusted` and `internal`. Other items are excluded with a reason code. A use case may explicitly allow untrusted content as data, but must retain its label and never promote its authority.
3. **Agent reasoning:** labels are context, not authorization. The model may still be influenced by injected instructions. Every proposed effect must go through the existing `AgentToolBoundary` and `GuardedGateway`.
4. **Output gate:** call `OutputBoundary.inspect` after generation and before returning content to a UI, sending a message, or invoking a renderer. Deliver only when `allowed=True`. If denied, do not deliver or render the original output; return a fixed safe error or regenerate under a constrained policy.

## Implemented checks

- Denies all Markdown image syntax (including reference-style images).
- Denies all raw HTML tags, including encoded spellings, because this boundary accepts plain text/Markdown rather than HTML.
- Denies raw HTML active elements (including image, iframe, script, SVG, form and embedded media), including data-URI and event-handler variants.
- Denies HTTP(S) links unless their host is explicitly allowlisted.
- Denies common credential patterns and configured sensitive values.
- Checks output type, Unicode validity and size.
- Enforces retrieval provenance and document/character budgets.

## Limits that must remain explicit

- HMAC provenance is only as safe as key custody. If untrusted code has access to the authority/key, it can issue a trusted label. HMAC verifies issuer possession and integrity; it does not establish that the source content is truthful or safe.
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
from paca_mvp.content_boundary import OutputBoundary, ProvenanceAuthority, filter_retrieval

# Illustrative only: load a unique random key (at least 32 bytes) from a secret manager.
# Only trusted ingestion code should receive the authority that can issue provenance.
authority = ProvenanceAuthority(provenance_key_from_secret_manager)
document = authority.issue("doc-123", "internal-kb", "trusted", "approved text")
retrieval = filter_retrieval(candidate_documents, authority=authority)
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
