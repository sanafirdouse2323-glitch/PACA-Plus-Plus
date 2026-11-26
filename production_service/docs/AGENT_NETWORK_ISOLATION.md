# Agent Network Isolation & Zero-Bypass Sandboxing

## 1. The Threat: Agent Host Bypass

A common vulnerability in AI agent architectures is **cooperative bypass**. If an agent host application routes registered tools through PACA++, but the LLM also has access to raw Python execution, generic HTTP libraries (`requests`, `httpx`), or shell access (`subprocess`), an adversarial prompt can instruct the agent to:
1. Open raw network sockets directly to external IP addresses.
2. Directly query internal microservices without passing through the Policy Enforcement Point (PEP).
3. Exfiltrate environment variables or stolen tokens to attacker-controlled C2 servers.

To achieve **Zero-Trust Compliance (NIST SP 800-207)**, software adapters must be backed by **kernel-level network isolation**. The agent must be physically incapable of routing traffic anywhere except the PACA++ gateway.

---

## 2. Docker Network Isolation Architecture

PACA++ provides an enterprise deployment profile (`compose.sandbox.yaml`) using segmented internal networks:

```
                    ┌──────────────────────────────────────────────┐
                    │               Isolated Host                  │
                    │                                              │
┌────────────────┐  │   ┌──────────────────────────────────────┐   │
│  Public Client │  │   │        Agent Sandbox Container       │   │
│ (User Prompt)  │──┼──>│  - Runs LangGraph / Agent Runtime    │   │
└────────────────┘  │   │  - NO DEFAULT INTERNET ROUTE         │   │
                    │   └──────────────────┬───────────────────┘   │
                    │                      │ internal: true        │
                    │                      ▼ (Port 8000 ONLY)      │
                    │   ┌──────────────────────────────────────┐   │
                    │   │         PACA++ Gateway (PEP)         │   │
                    │   │  - Validates DPoP & RS256 JWT        │   │
                    │   │  - Checks OPA Rego Policies          │   │
                    │   │  - Signs Postgres HMAC Session RLS   │   │
                    │   └──────┬───────────────────────┬───────┘   │
                    │          │                       │           │
                    │          ▼ control-plane         ▼ egress    │
                    │   ┌──────────────┐       ┌───────────────┐   │
                    │   │  OPA & DB    │       │ Allowed Tools │   │
                    │   │ (PostgreSQL) │       │ & Upstream API│   │
                    │   └──────────────┘       └───────────────┘   │
                    └──────────────────────────────────────────────┘
```

### Network Topology Guarantees:
1. **`agent-isolated` Network:** Defined with `internal: true`. Docker creates a bridge network with **no default gateway**. The agent container cannot resolve external DNS or route packets to the public internet.
2. **Single Authorized Path:** The only container sharing the `agent-isolated` network is the `paca-gateway`.
3. **No Raw Egress:** Even if an injected prompt forces the LLM to run `import urllib; urllib.request.urlopen("https://evil.com")`, the OS kernel drops the packet immediately with `Network unreachable`.

---

## 3. Production Deployment with iptables / Linux Namespaces

For bare-metal or Kubernetes deployments, enforce isolation using network namespaces and `iptables`:

```bash
# 1. Create a dedicated network namespace for the agent
ip netns add agent-ns

# 2. Configure veth pair linking agent-ns to the paca-gateway bridge
ip link add veth-agent type veth peer name veth-paca
ip link set veth-agent netns agent-ns

# 3. Restrict egress: DROP all outbound traffic except TCP port 8000 to the gateway IP
ip netns exec agent-ns iptables -A OUTPUT -o lo -j ACCEPT
ip netns exec agent-ns iptables -A OUTPUT -p tcp -d 172.20.0.10 --dport 8000 -j ACCEPT
ip netns exec agent-ns iptables -A OUTPUT -j DROP
```

---

## 4. Verification

Run the sandbox integration stack:
```bash
docker compose -f compose.sandbox.yaml up -d
docker compose -f compose.sandbox.yaml exec agent-runtime curl -I https://google.com
# Output: curl: (7) Failed to connect (Network unreachable)

docker compose -f compose.sandbox.yaml exec agent-runtime curl -I http://paca-gateway:8000/healthz
# Output: HTTP/1.1 200 OK {"status":"ok"}
```
