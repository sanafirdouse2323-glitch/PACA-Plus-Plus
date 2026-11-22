# PACA++ — Policy-Aware Authorization and Controlled Action

**PACA++** is an enterprise-grade Policy Enforcement Point (PEP) and Controlled Action Gateway designed to secure microservices and autonomous AI agent tool boundaries. 

The core architectural problem PACA++ solves is **preventing unauthorized, duplicated, or parameter-tampered effects** by cryptographically binding authorization decisions to the verified principal, tenant, action, resource, argument digest, and policy revision at the exact moment of execution.

---

## Repository Lineage & Sister Project

* **PACA++ (This Repository):** Focuses on **Service-Level Policy Enforcement & Multi-Tenant Isolation** using FastAPI, Open Policy Agent (OPA), PostgreSQL Row-Level Security (RLS), and LangGraph execution adapters.
* **[PACA-Plus-Plus-New](https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus-New):** A distinct sibling research project focusing on **Provenance-Anchored Continuous Authorization**—an in-process reference monitor that tracks data taint and capability attenuation across multi-turn LLM reasoning.

*Do not conflate the two implementations: this repository enforces policy at the network/service boundary, whereas PACA-Plus-Plus-New enforces policy inside the agent's internal cognitive pipeline.*

---

## Architectural Components

```
PACA-Plus-Plus/
├── production_service/    # [Core] Production FastAPI Gateway + OPA + PostgreSQL RLS
├── agent/                 # [Integration] LangGraph StateGraph/ToolNode adapter & client
├── prototype/             # [Research] In-memory & SQLite research prototype
├── compiler/              # [Experimental] ALFA to ASP / Cedar transpiler subset
└── legacy_policy_engine/  # [Archival] Historical policy parser & evaluator
```

### 1. `production_service/` (Core Enterprise Gateway)
The primary deployable artifact. It implements a hardened Policy Enforcement Point:
* **Token Authentication:** Verifies RS256 JWTs against a configured HTTPS JWKS endpoint, enforcing issuer, audience, expiration, and strict `token_use=access` claims.
* **Policy Decision Point (PDP):** Communicates with an Open Policy Agent (OPA) instance evaluating Rego policies against trusted server-side resource facts.
* **Two-Phase Enforcement Protocol:**
  1. `POST /v1/authorizations`: Evaluates request context and returns a short-lived cryptographic `permit_id`.
  2. `POST /v1/executions`: Re-verifies the permit, argument hash, and policy revision before invoking the target adapter.
* **Database Multi-Tenant Isolation:** PostgreSQL Row-Level Security (RLS) driven by a short-lived HMAC-signed session context bound to `(tenant_id, principal_id, backend_pid, txid)`.
* **Durable Idempotency:** Tracks execution states to prevent duplicate external actions during network retries.

### 2. `agent/` (AI-Agent Boundary Integration)
* **Standard Library Client (`paca_client.py`):** Dependency-free client executing the two-phase `/authorize` → `/execute` flow.
* **LangGraph Adapter (`langgraph_adapter.py`):** Configures a LangGraph `ToolNode` / `StateGraph` where registered tools automatically route through the PACA authorization gateway before execution.

### 3. `prototype/`, `compiler/`, & `legacy_policy_engine/`
Historical and experimental research packages preserved for reference:
* `prototype/`: In-memory sandbox for local policy experiments.
* `compiler/transpiler.py`: Experimental 172-line transpiler mapping a small ALFA subset to ASP (Clingo) and Cedar.
*(Note: These packages are separate from the production gateway; policies written in ALFA cannot be evaluated by the OPA-based production service).*

---

## Enterprise Zero-Trust Evaluation

| Enterprise Requirement | Implemented Architecture | Production Deployment Requirement |
|---|---|---|
| **Zero Trust Access** | Callers authenticated per-request via RS256 JWT; decisions made by OPA | Connect to enterprise IdP (Okta, Entra ID, Keycloak) with strict claim mapping |
| **Cross-Tenant Isolation** | PostgreSQL RLS with HMAC-signed session context | Separate runtime DB credentials from migration roles; enable DB TLS |
| **Agent Action Safety** | LangGraph tool adapter forces calls through PEP | Isolate agent host containers to prevent raw socket/shell bypass |
| **Replay & Concurrency** | Two-phase permit validation with idempotency keys | Ensure downstream APIs support idempotent deduplication |
| **Audit Integrity** | Append-only execution and audit logging | Stream audit logs to enterprise SIEM / WORM storage |

---

## Enterprise Production-Hardening Checklist (Priority 0 Gaps)

Before deploying this gateway to process sensitive corporate workloads:
1. **Secrets Management:** Replace all checked-in HMAC and database keys with credentials managed by AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault.
2. **Sender-Constrained Tokens:** Upgrade from bearer JWTs to DPoP (RFC 9449) or mutual TLS (mTLS) to prevent token theft and replay attacks.
3. **Token Revocation:** Integrate an active token revocation check / denylist service at the gateway ingress.
4. **Approval Workflows:** For destructive actions (e.g. fund transfers, data deletion), attach an asynchronous human-in-the-loop (HITL) approval service to the permit verification stage.
5. **Host Isolation:** Sandbox the AI agent execution host (e.g., via gVisor or microVMs) to ensure the LLM cannot bypass the LangGraph adapter via unmanaged network or shell tools.
