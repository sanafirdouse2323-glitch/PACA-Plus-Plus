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
try:
    result = paca.authorize_and_execute(
        action="file.read",
        resource_id="report-123",
        arguments={},
        idempotency_key="job-2026-00042-read-report",
    )
except PACARequestError as exc:
    # For status=None or an unknown execution outcome, reconcile before retrying.
    print(exc.status, exc.body)
else:
    print(result)
```

Use HTTPS for any non-loopback deployment. Do not put access tokens in prompts, tool arguments, logs or source control. Obtain tokens through the host application's trusted OIDC flow. The server must provision the resource and its trusted authorization facts; a caller-provided resource ID is not proof of ownership.

## Agent-framework integration contract

- The model may propose an action, but the host validates it against a server-configured tool/resource registry.
- The host, not the model, supplies the authenticated access token and stable idempotency key.
- The host routes the actual effect through PACA++; it must not execute the same action directly as a fallback.
- Treat retrieved content and tool output as untrusted data. Authorization does not make prompt-injection content safe.
- A timeout or transport error can leave the remote outcome uncertain. Reconcile the execution/downstream state before retrying; never generate a new idempotency key for the same logical effect.
- This helper does not integrate a particular LangChain, LangGraph, AutoGen, CrewAI or other framework. Framework-specific adapters and bypass testing remain deployment work.

## Test

From the repository root:

```sh
python -m unittest discover -s agent/tests -v
```

This is a thin HTTP client integration test using a local test server. It is not a live OIDC, production gateway or real-agent security evaluation.
