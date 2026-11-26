# PACA++: Policy Enforcement Gateway for AI Agents & Services

PACA++ is an authorization gateway designed to stop AI agents and microservices from taking unauthorized or unintended actions.

### The Problem It Solves
When an autonomous AI agent decides to execute a tool—whether that's writing to a customer database, sending an email, or triggering an API payment—how do you know the action actually matches the authenticated user's permissions and hasn't been altered?

Most agent guardrails today try to inspect prompt text to catch attacks. But if a clever prompt injection slips through, the model will still try to run the tool. 

PACA++ takes a deterministic approach: it sits between the AI agent and your sensitive systems. Even if an agent's internal reasoning gets hijacked, it cannot touch a protected resource without passing strict, server-side policy checks.

---

## How It Works (The Two-Phase Check)

Instead of letting an agent call an external API directly, PACA++ uses a two-step handshake:

```
[ AI Agent / Client ]                [ PACA++ Gateway ]               [ Policy & DB ]
        |                                    |                                |
        |--- 1. POST /v1/authorizations ---->|                                |
        |    (Action, Resource, Arguments)   |--- Evaluate with OPA --------->|
        |<-- 2. Returns short-lived permit --|    (Returns permit_id)         |
        |                                    |                                |
        |--- 3. POST /v1/executions -------->|                                |
        |    (Permit_id + Idempotency-Key)   |--- Re-verify context & hash -->|
        |                                    |--- Lock & check tenant RLS --->|
        |                                    |--- Run Action via Adapter ---->|
        |<-- 4. Returns execution result ----|                                |
```

1. **Step 1: Authorization (`/v1/authorizations`)**  
   The agent submits what it wants to do (the action, target resource, and arguments) along with its verified JWT access token. PACA++ checks the request against Open Policy Agent (OPA) rules. If allowed, it returns a temporary, cryptographically bound `permit_id`.
2. **Step 2: Execution (`/v1/executions`)**  
   The agent submits the `permit_id` along with an idempotency key. PACA++ re-verifies that the arguments and policy revision haven't changed, confirms tenant isolation in PostgreSQL, and only then triggers the actual downstream action. If a network drop happens, the idempotency key prevents duplicate execution.

---

## What's in This Repository

This repository contains several components developed across our research:

* **`production_service/` (The Core Gateway):**  
  The main deployable FastAPI service. It handles RS256 JWT authentication, calls OPA for Rego policy decisions, enforces PostgreSQL Row-Level Security (RLS) using HMAC session tokens, and records audit logs. Includes RFC 9449 DPoP sender-constrained token validation, W3C distributed tracing context propagation (`traceparent`), and isolated container network configurations (`compose.sandbox.yaml`).
* **`agent/` (AI Agent Integration):**  
  A Python client and reference adapter for **LangGraph** (`StateGraph` / `ToolNode`). When registered, the agent's tools automatically route through PACA++ before running.
* **`prototype/` (Research Prototype):**  
  An earlier in-memory and SQLite testbed used for local experiments.
* **`compiler/` & `legacy_policy_engine/`:**  
  Historical experiments exploring how to compile high-level ALFA policies into ASP (Answer Set Programming) and Amazon Cedar. *(Note: policies in the production service use OPA Rego, not ALFA).*

---

## Relationship with `PACA-Plus-Plus-New`

We have two separate repositories under the PACA++ research project:

1. **This repository (`PACA-Plus-Plus`):** Focuses on the **external gateway**. It treats the agent as an untrusted client and enforces policies at the HTTP and database boundary using OPA and PostgreSQL.
2. **[`PACA-Plus-Plus-New`](https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus-New):** Focuses on the **agent's internal reasoning**. It is a standalone Python reference monitor that tracks data taint (provenance) across multi-turn LLM reasoning to prevent sensitive data from reaching unauthorized tools.

The two projects complement each other: one protects the outer network/API boundary, while the other monitors the inner agent data flow.

---

---

## Enterprise Hardening & Isolation Controls

Beyond basic API gateway routing, deploying an authorization proxy for autonomous agents in enterprise environments requires defending against agent compromise, token theft, and network bypass:

1. **Agent Network Egress Isolation (`production_service/compose.sandbox.yaml` & `docs/AGENT_NETWORK_ISOLATION.md`)**:
   If an LLM agent has unrestricted network access or raw shell capabilities, it can bypass local application adapters and talk to internal services directly. PACA++ specifies a strict network sandbox (`internal: true` bridge network) where agent containers have zero direct internet or intranet access; all outbound HTTP/tool traffic must traverse the PACA++ enforcement proxy.

2. **Sender-Constrained Proofs via RFC 9449 DPoP (`production_service/paca_service/dpop.py`)**:
   Bearer tokens present an exfiltration risk if logged or intercepted. PACA++ implements Demonstrating Proof-of-Possession (DPoP) at the HTTP layer, binding each access token to an ephemeral client RSA/EC key pair, verifying `jkt` thumbprints, HTTP method/URI signatures, and server-issued nonces to eliminate token replay attacks.

3. **End-to-End W3C Distributed Tracing (`production_service/paca_service/telemetry.py`)**:
   Every agent action request carries a standard W3C `traceparent` identifier. The gateway propagates this trace across the OPA policy check, PostgreSQL permit generation, and downstream tool execution, ensuring a verifiable causal audit trail from agent prompt reasoning to final database write.

## Running It Locally

### Requirements
* Python 3.10+
* Docker and Docker Compose (for OPA and PostgreSQL)

### Quick Start
```bash
# Clone the repository
git clone https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus.git
cd PACA-Plus-Plus/production_service

# Install dependencies
pip install -r requirements.txt

# Start local PostgreSQL and OPA containers
docker compose up -d

# Run tests
pytest
```

---

## What You Need for a Real Production Deployment

If you are planning to deploy this gateway in an enterprise environment, here is what you need to set up first:
1. **Identity Provider:** Connect a real OIDC provider (Okta, Keycloak, or Microsoft Entra ID) to issue RS256 access tokens.
2. **Secrets:** Replace the example HMAC keys and database passwords with secrets from your cloud secret manager (AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault).
3. **Database Roles:** Apply the PostgreSQL schema migrations and set up least-privilege runtime credentials.
4. **Agent Sandboxing:** Run your AI agents in isolated containers (e.g. Docker or gVisor) so they cannot bypass the gateway by opening raw network sockets or running shell commands directly.
