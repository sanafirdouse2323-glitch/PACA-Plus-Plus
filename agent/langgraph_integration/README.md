# PACA++ LangGraph integration

This package integrates the production-service PACA++ authorize/execute API into a real LangGraph tool-calling graph. It is an adapter, not a replacement for the PACA++ decision point.

## Security boundary

- The model sees only the tools returned by \`build_paca_tools\`. Each tool maps to a host-configured \`ActionSpec.action\`; the model cannot select an arbitrary PACA++ action.
- A protected tool obtains a permit through \`POST /v1/authorizations\` and executes through \`POST /v1/executions\`. A denied authorization never sends the execution request.
- The graph propagates tool exceptions to the host. An unknown execution result does not become a success message to the model.
- The SQLite operation ledger persists the LangGraph \`thread_id\`, \`tool_call_id\`, request digest, permit ID, stable idempotency key and result. Replaying the same call reuses its permit and key. A new tool-call ID for an equivalent unresolved operation in the same thread is blocked pending reconciliation.
- Optional \`allowed_resource_ids\` in an \`ActionSpec\` provides an additional host allowlist. When omitted, the service-side trusted resource lookup and policy must decide whether the requested resource is allowed. A model-supplied resource ID is never proof of ownership.

**This integration cannot prove that the surrounding host application has no alternate route to a database, filesystem, browser or remote API.** The application must not expose unguarded tools, direct effect clients, SQL write connections or fallback handlers for protected resources alongside this graph. Keep credentials for downstream effects out of the model process where practical and constrain the network so the host cannot bypass PACA++.

## Minimal usage

Install the optional dependency set:

\`\`\`sh
python -m pip install -r agent/requirements-langgraph.txt
\`\`\`

Configure a \`PACAClient\` with the access token supplied by the host's trusted identity-provider integration. Token acquisition and refresh are deliberately outside this stage.

\`\`\`python
from agent.paca_client import PACAClient
from agent.langgraph_integration.paca_tools import (
    ActionSpec,
    SQLiteOperationLedger,
    build_paca_langgraph_agent,
)

paca = PACAClient(
    base_url="https://paca.example.org",
    access_token=trusted_access_token,
)
ledger = SQLiteOperationLedger("/var/lib/paca/langgraph-operations.sqlite3")

agent = build_paca_langgraph_agent(
    model=chat_model,
    client=paca,
    ledger=ledger,
    actions=[
        ActionSpec(
            tool_name="read_document",
            action="file.read",
            description="Read a document that the current principal is authorized to access.",
        ),
    ],
)

result = agent.invoke(
    {"messages": [("user", "Read report-123 as text.")]},
    config={"configurable": {"thread_id": "conversation-2026-0007"}},
)
\`\`\`

Use a persistent, access-controlled ledger path. Back up and monitor it. The bundled SQLite ledger is for a single host; it is not a multi-host coordination database or an independent audit store. Before multi-worker/multi-host use, replace it with a shared transactional store that enforces the same uniqueness and pending-operation constraints.

## Retry and recovery

The ledger uses the LangGraph thread and tool-call IDs to derive a stable PACA++ idempotency key. It stores the permit before sending execution. For a timeout, lost response or unexpected status, the operation is recorded as unknown and the graph raises to the host. Reconciliation is required before a new logical tool call can duplicate the same request in that thread. Replaying the original tool-call identity uses the original permit and idempotency key; the downstream API must honor its idempotency contract.

A local ledger cannot make a remote API side effect exactly-once. Do not automatically rerun an unresolved operation after a process restart. Query PACA++ execution status and reconcile with the downstream system first.

## Tests

The tests use a local HTTP test server and a deterministic fake chat model. They exercise the actual LangGraph \`StateGraph\` and \`ToolNode\` execution path without calling an external model provider. They verify successful authorize/execute flow, deny-before-execute, unknown-outcome retry identity, duplicate prevention and rejection of an undeclared direct-effect tool.

This is real framework integration evidence, not an independent security audit, benchmark, or proof that a complete application has no non-LangGraph bypass.
