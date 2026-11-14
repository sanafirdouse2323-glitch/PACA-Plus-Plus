# PACA++ host-side agent integration

The production service is an authorization/effect gateway, not an LLM agent framework. A host application must send every protected operation through the gateway and must not also expose a direct, unguarded tool path.

## Minimal client

`paca_client.py` uses only the Python standard library. It performs the production service's two-phase protocol:

1. POST the exact action, resource ID and arguments to `/v1/authorizations`.
2. Receive a short-lived permit.
3. POST the same action, resource ID and arguments plus that permit ID to `/v1/executions`, with a stable `Idempotency-Key`.

Example:

```python
from agent.paca_client import PACAClient, PACARequestError

paca = PACAClient(
    base_url="http://127.0.0.1:8000",
    access_token="<access token from your configured OIDC provider>",
)
# Use a stable key for this logical operation and retain the permit ID.
idempotency_key = "job-2026-00042-read-report"
permit = paca.authorize(
    action="file.read",
    resource_id="report-123",
    arguments={},
)
permit_id = permit["permit_id"]

try:
    result = paca.execute(
        action="file.read",
        resource_id="report-123",
        arguments={},
        permit_id=permit_id,
        idempotency_key=idempotency_key,
    )
except PACARequestError as exc:
    # The permit ID and idempotency key must be retained across retries.
    # Retry execute() with the same values; never authorize a new permit
    # merely because the execution response timed out.
    print(exc.status, exc.body, permit_id)
else:
    if result.get("status") == "unknown":
        # Query status and reconcile with the downstream service before any
        # decision to retry or compensate.
        print(paca.execution_status(result["execution_id"]))
    else:
        print(result)
```

Use HTTPS for any non-loopback deployment. Do not put access tokens in prompts, tool arguments, logs or source control. Obtain tokens through the host application's trusted OIDC flow. The server must provision the resource and its trusted authorization facts; a caller-provided resource ID is not proof of ownership.

## Agent-framework integration contract

- The model may propose an action, but the host validates it against a server-configured tool/resource registry.
- The host, not the model, supplies the authenticated access token and stable idempotency key.
- The host routes the actual effect through PACA++; it must not execute the same action directly as a fallback. For retries, persist and reuse the original permit ID and idempotency key. Calling `authorize_and_execute()` again obtains a new permit and is not a safe retry of an earlier execution.
- Treat retrieved content and tool output as untrusted data. Authorization does not make prompt-injection content safe.
- A timeout or transport error can leave the remote outcome uncertain. Reconcile the execution/downstream state before retrying; never generate a new idempotency key for the same logical effect.
- The minimal HTTP client is framework-neutral. The optional [LangGraph adapter](langgraph_integration/README.md) is a concrete integration; AutoGen, CrewAI, MCP and other framework adapters remain separate work.

## Test

From the repository root:

```sh
python -m unittest discover -s agent/tests -v
```

This is a thin HTTP client integration test using a local test server. It is not a live OIDC, production gateway or real-agent security evaluation.

## LangGraph integration

See [the PACA++-guarded LangGraph integration](langgraph_integration/README.md). It provides a real LangGraph `StateGraph` and `ToolNode` path in which the model-visible tools are created only from host-owned PACA++ action specifications. It uses a persistent SQLite operation ledger for stable thread/tool-call idempotency identity and requires a `thread_id` on each graph invocation. This is a single-host coordination aid, not a shared multi-host database or independent audit store.

Install and test the optional adapter with:

```sh
python -m pip install -r agent/requirements-langgraph.txt
python -m pytest agent/tests/test_langgraph_integration.py -q
```

The tests use a deterministic fake chat model to exercise the real LangGraph execution engine and a local fake PACA++ HTTP endpoint. They do not make a call to a hosted LLM provider or prove that an entire external host application has no direct-effect bypass.
