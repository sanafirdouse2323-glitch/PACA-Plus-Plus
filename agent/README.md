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
- This helper does not integrate a particular LangChain, LangGraph, AutoGen, CrewAI or other framework. Framework-specific adapters and bypass testing remain deployment work.

## Test

From the repository root:

```sh
python -m unittest discover -s agent/tests -v
```

This is a thin HTTP client integration test using a local test server. It is not a live OIDC, production gateway or real-agent security evaluation.

## LangGraph production-service adapter

```text
agent/langgraph_adapter.py
agent/langgraph_tests/test_langgraph_adapter.py
agent/requirements-langgraph.txt
```

This is a real LangGraph `StateGraph` integration, separate from the prototype's vendor-neutral
`GuardedAgentRuntime`. The model is bound only to a host-configured allowlist of
`PACAOperation` tools. Each tool fixes its PACA action in host configuration, accepts a
strict Pydantic argument schema, extracts the resource ID, then calls the production
gateway's `authorize()` and `execute()` endpoints. The model cannot choose an arbitrary
action, resource route, endpoint URL, or unregistered tool name.

Install the pinned integration dependencies from the repository root:

```sh
python -m pip install -r agent/requirements-langgraph.txt
```

The adapter requires three independent persistence components:

- A durable LangGraph checkpointer preserves graph state and unfinished tool calls.
- A durable LangGraph `BaseStore` is provided to the graph for framework-level storage. It is **not** the protected-operation journal and its get/put calls are not treated as transactional.
- A `PostgresOperationLedger` stores the request fingerprint, PACA permit ID, stable idempotency key, lease and terminal execution outcome in a dedicated PostgreSQL schema. Its primary key is a hash of the LangGraph thread/tool-call identity. A transaction and short lease serialize concurrent workers for the same protected operation.

Apply `agent/migrations/0001-operation-ledger.sql` with a migration role in the dedicated LangGraph persistence database. Give the runtime role only `USAGE` on `paca_langgraph` and `SELECT, INSERT, UPDATE` on `paca_langgraph.execution_journal`. Do not use the PACA service database or grant the agent access to `paca_private`. The runtime role must not own the schema or table in production.

Example wiring (the model object is supplied by the host's chosen provider package):

```python
import os

from langchain_core.messages import HumanMessage
from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.store.postgres import PostgresStore

from agent.langgraph_adapter import (
    PACAArgsModel,
    PACAOperation,
    build_paca_langgraph_agent,
)
from agent.paca_client import PACAClient
from pydantic import Field

# Enable the strict checkpoint deserializer before constructing PostgresSaver.
os.environ["LANGGRAPH_STRICT_MSGPACK"] = "true"

class ReadFileArgs(PACAArgsModel):
    resource_id: str = Field(min_length=1, max_length=256)
    format: str = Field(default="text", pattern="^(text|json)$")

model = configured_tool_calling_chat_model  # Provider-specific; must support bind_tools().
paca = PACAClient(
    base_url=os.environ["PACA_BASE_URL"],
    access_token=os.environ["PACA_ACCESS_TOKEN"],
)

operation = PACAOperation(
    name="read_file",
    description="Read a file through PACA++ policy authorization.",
    action="file.read",
    resource_id_field="resource_id",
    args_schema=ReadFileArgs,
)

database_url = os.environ["LANGGRAPH_DATABASE_URL"]
operation_ledger = PostgresOperationLedger(database_url, claim_ttl_seconds=120)
operation_ledger.open()
try:
    with PostgresSaver.from_conn_string(database_url) as checkpointer:
        checkpointer.setup()
        with PostgresStore.from_conn_string(database_url) as store:
            store.setup()
            graph = build_paca_langgraph_agent(
                model=model,
                paca_client=paca,
                operations=[operation],
                checkpointer=checkpointer,
                store=store,
                operation_ledger=operation_ledger,
            )
            config = {"configurable": {"thread_id": "stable-host-generated-thread-id"}}
            result = graph.invoke(
                {"messages": [HumanMessage(content="Read the approved report.")]},
                config,
            )
finally:
    operation_ledger.close()
```

Important deployment constraints:

- Use a dedicated, access-controlled LangGraph persistence database and least-privilege database role. Do not reuse the PACA++ production-service database credentials or grant the LangGraph worker access to PACA's private signing-key schema.
- Run Postgres saver/store schema setup through a reviewed migration role. Follow the installed package's security guidance for checkpoint deserialization; do not load untrusted checkpoint data with permissive deserialization.
- Use a durable Postgres-backed checkpointer and store in deployment. `InMemorySaver` and `InMemoryStore` are used only by tests and local experiments.
- The PostgreSQL operation ledger grants one worker a short lease for an authorized operation. Set its lease longer than the PACA gateway request timeout and expected call duration. If a worker crashes, the lease expires; a subsequent attempt reuses the original permit and idempotency key. The gateway must enforce idempotency for this recovery to be safe.
- If a tool call errors after the execution request, resume the same unfinished graph thread with `graph.invoke(None, config)`, not a fresh user input. The journal reuses the same permit and idempotency key. For an unknown outcome, reconcile the execution with the gateway/downstream system; do not create a new tool call or idempotency key for the same effect.
- Do not add raw side-effecting tools to the model or `ToolNode`, and do not create other host code paths that call downstream effects directly. Network egress and downstream authorization controls are still needed to stop bypasses outside this graph.
- `PACAClient` currently uses a caller-supplied access token. Token acquisition/refresh, sender-constrained tokens, and revocation are Stage 3 work, not implemented by this adapter.

The automated tests execute a real LangGraph `StateGraph` and `ToolNode` with a deterministic
fake chat model and a test gateway client. They verify registered calls, rejection of an
unregistered tool, rejection of model-supplied extra action fields, permit/key reuse after
a lost response, PostgreSQL uniqueness and worker leases, and process reconstruction using
the PostgreSQL checkpointer, store and operation ledger. The persistence test exercises a
real PostgreSQL instance in CI; its model and PACA gateway client remain deterministic test
doubles. It does not prove that every side effect in an arbitrary host application or
deployed environment is routed through PACA++. That requires host-specific OS/network
isolation and independent bypass testing.


## Containerized host-bypass isolation harness

Run the reproducible Linux/Docker boundary test from the repository root:

```sh
bash agent/security_harness/run.sh
```

The harness creates two isolated internal Docker networks. The agent container is attached only to the gateway network; the mock PACA gateway is attached to both networks; and the protected PostgreSQL and downstream API services are attached only to the backend network. The protected test file is mounted into the gateway container, not the agent container. The agent runs as a non-root UID with a read-only root filesystem, dropped Linux capabilities, no-new-privileges, and no external network egress. The script creates a short-lived test-only TLS certificate so the agent uses the real `PACAClient` over verified HTTPS.

The probe asserts that direct protected-file reads, root-filesystem writes, database connections, downstream API connections and arbitrary internet egress are blocked, while the PACA authorize/execute path remains reachable. The gateway, database and API in this harness are test services—not the production gateway or production host. This is evidence that the declared Docker topology enforces those specific boundaries; it does not certify a deployment, prove every host kernel/runtime configuration, or replace testing the actual host application's mounts, credentials, firewall and orchestration policies. Never reuse the harness certificate or token in a real deployment.
