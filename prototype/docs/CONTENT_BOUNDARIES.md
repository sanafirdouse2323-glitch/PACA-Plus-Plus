# PACA++ content boundaries: retrieval, output, and trust

## Why this layer exists

The incident review identifies two gaps a tool-call gate alone does not cover: retrieval-phase provenance filtering and output-formatting exfiltration. This module adds deterministic enforcement at those boundaries without duplicating the existing authorization, OPA, durable-permit, or tool-routing checks.

## Request path

1. **Ingestion:** a trusted component assigns each document a source identifier and trust label: `trusted`, `internal`, `untrusted`, or `unknown`. It issues provenance using `ProvenanceAuthority.issue`; an HMAC binds the document ID, source, source-policy-derived trust label and content digest. Trust levels come from an administrator-configured source-to-trust mapping; unregistered sources become `unknown`. The issuer does not accept a caller-supplied trust label. Never derive trust from the document's own claims or model-generated metadata. Keep the HMAC key only in trusted ingestion/retrieval code; never expose it to an LLM, plugin or tool output. For separate ingestion and retrieval services, use an asymmetric signing service instead of distributing the HMAC secret.
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

- HMAC-authenticated provenance is only as safe as key custody. If untrusted code has access to the authority/key, it can issue a trusted label. HMAC verifies issuer possession and integrity; it does not establish that the source content is truthful or safe.
- This is not a universal prompt-injection detector and does not reliably detect every secret, PII item, encoded payload, steganographic channel or covert channel.
- This module does not inspect image pixels/OCR, audio, video, or other non-text inputs. Image-embedded instructions require a separately implemented multimodal inspection path; they are not made safe by text provenance or output checks.
- The host allowlist must be administrator-controlled. An allowed host can still leak data through query parameters; only allow hosts that are safe to receive the output.
- This checks output text, not every downstream client's behavior. Clients need restrictive rendering, disabled raw HTML/remote images, CSP and network-egress policy as appropriate.
- Provenance is only as reliable as trusted ingestion. If an LLM can set `trust="trusted"`, this gate is bypassed by design.
- Default retrieval filtering can reduce recall. Where untrusted sources are needed, retain their labels and enforce effects out-of-band.
- This does not prevent platform bugs, compromised dependencies, direct calls to separately exposed endpoints, or unsafe executor code. Use sandboxing, least privilege and ordinary application security controls.
- Planning/SMT verification remains a separate hypothesis. No solver or formal proof is implemented here.
- The separate [inter-agent message boundary](INTER_AGENT_BOUNDARY.md) validates host-authenticated sender/recipient routes and keeps accepted messages explicitly untrusted. It does not authenticate the transport, grant capabilities, or semantically detect cross-agent prompt injection; those remain separate responsibilities/gaps.

## Minimal integration pattern

```python
from paca_mvp.content_boundary import OutputBoundary, ProvenanceAuthority, filter_retrieval

# Illustrative only: load a unique random key (at least 32 bytes) from a secret manager.
# Only trusted ingestion code should receive the authority that can issue provenance.
authority = ProvenanceAuthority(
    provenance_key_from_secret_manager,
    source_trust_levels={"internal-kb": "trusted", "web": "untrusted"},
)
document = authority.issue("doc-123", "internal-kb", "approved text")
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

### One facade for the full boundary

Use `GuardedAgentPipeline` in the host orchestrator so retrieval, model-proposed tool calls, and user-visible output use the same configured boundaries. Deliver only the string returned by `release_output`; if it raises `OutputBlocked`, do not deliver the original model output.

```python
from paca_mvp import (
    GuardedAgentPipeline, ProvenanceAuthority, OutputBoundary,
)

pipeline = GuardedAgentPipeline(
    provenance_authority=provenance_authority,
    tool_boundary=agent_tool_boundary,
    output_boundary=OutputBoundary(allowed_link_hosts=("docs.example.org",)),
)
retrieval = pipeline.retrieve(candidate_documents)
tool_result = pipeline.invoke_tool(tool_call, call_id=trusted_operation_id)
safe_text = pipeline.release_output(generated_text)
deliver_to_user(safe_text)  # never deliver generated_text directly
```

The repository does not implement an LLM generation loop; the host application must use this facade on every relevant path. It cannot stop a separate code path from bypassing the facade or calling an exposed downstream endpoint directly.

The example host and sensitive value are placeholders. Do not log raw blocked output by default because it may contain the secret that triggered the block.

## Validation

Run from `prototype/`:

```bash
python -m unittest discover -s tests -v
```
