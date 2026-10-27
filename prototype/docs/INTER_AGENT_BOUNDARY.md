# Inter-agent message boundary

## Purpose

The incident review identifies cross-agent trust propagation as an underspecified area. This module is a narrow deterministic baseline: it checks a configured sender-to-recipient route, binds the sender field to an identity supplied by an independently authenticated host transport, limits message size and receive attempts, rejects replayed message IDs within one receiver-run instance, and marks every accepted message as untrusted.

It does **not** perform semantic prompt-injection detection. A message may be correctly sent by an authenticated agent and still contain malicious instructions, misleading claims, or a request to exceed that agent's authority.

## Integration contract

- The host transport must authenticate the sending agent independently (for example, with a suitable service identity or mutually authenticated channel). Only then pass that verified identity as authenticated_sender_id.
- Route configuration must be administrator-controlled. This module does not accept sender IDs, trust labels, roles, or capabilities from the message envelope.
- Envelopes contain exactly message_id, recipient_id, and content. The recipient must also match the host's expected receiving context.
- Accepted messages always carry the fixed trust label untrusted_agent_message. Do not promote that label based on the sender name or content.
- Messages do not delegate tool permissions or approval. Every resulting model-proposed action must still pass AgentToolBoundary and the protected GuardedGateway.

## Example

~~~python
from paca_mvp.inter_agent_boundary import InterAgentMessageBoundary

boundary = InterAgentMessageBoundary({
    "research-agent": ("summary-agent",),
    "summary-agent": ("review-agent",),
})
message = boundary.receive(
    {"message_id": "msg-104", "recipient_id": "summary-agent", "content": "Candidate findings"},
    authenticated_sender_id=verified_transport_sender,
    expected_recipient_id="summary-agent",
)
# Keep message.content as untrusted data; never treat it as policy or authorization.
~~~

## Limits

- The authenticated_sender_id argument is a trusted integration input. This class does not verify certificates, JWTs, signatures, or transport identity itself; a caller that supplies an unverified identity can bypass the intent of this boundary.
- Replay tracking and message budgets are in memory and scoped to one boundary instance. They reset on process restart and are not a distributed replay store.
- The message body is not semantically classified and is not sanitized. Content from a legitimate agent can still contain prompt injection. The recipient must maintain trust separation and enforce all tool effects independently.
- No capabilities are inherited from the sender. If delegated authority is needed, it must be represented by a separate authenticated, scoped, expiring, one-use authorization mechanism.
- This is not a full multi-agent protocol and does not inspect images, audio, video, or other multimodal payloads.

## Tests

From the prototype directory, run:

~~~bash
python -m unittest discover -s tests -v
~~~
