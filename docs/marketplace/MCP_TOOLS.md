# MCP Tool Reference

The Agent Authorization Gateway exposes a unified MCP server with 17 unique tools (plus 5 backward-compatibility aliases, 22 total) spanning all five agents in the system. Any MCP-compatible client (Claude Desktop, ADK agents, LangChain, CrewAI) can connect and invoke the full capability set during reasoning. Agent registration is not available via MCP — it requires proof of possession, enforced only via the REST API.

**Endpoint**: `https://agent-auth-gateway-mcp-1031148889398.us-central1.run.app/mcp`
**Auth**: Bearer token (`Authorization: Bearer <MCP_AUTH_TOKEN>`)

## Connection Example

```python
import asyncio
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async def main():
    url = "https://agent-auth-gateway-mcp-1031148889398.us-central1.run.app/mcp"
    headers = {"Authorization": "Bearer <MCP_AUTH_TOKEN>"}
    async with streamablehttp_client(url, headers=headers) as (r, w, _):
        async with ClientSession(r, w) as session:
            await session.initialize()
            tools = await session.list_tools()
            for t in tools.tools:
                print(f"{t.name}: {t.description[:60]}...")

asyncio.run(main())
```

---

## Gateway Tools (5)

In-process tools for authorization and receipt verification. Agent registration requires proof of possession and is available only via the REST API (`POST /agents/register-challenge` + `POST /agents/register`).

### `gateway_authorize_action`

Evaluate an AI agent's intended action against a security policy. Returns an authorization decision (approve/deny) with a cryptographic receipt and, if approved, a 60-second scoped token.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent_id` | string | yes | Unique identifier of the requesting agent |
| `action` | string | yes | Intended action (e.g., "read", "write", "delete") |
| `resource` | string | yes | Target resource (e.g., "staging-database") |
| `agent_proof` | string | yes | DPoP-style proof JWT signed by the agent's Ed25519 key |
| `parameters` | string | no | JSON string of action-specific parameters |

### `gateway_verify_receipt`

Verify a receipt's Ed25519 signature, canonical hash, and chain linkage.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `receipt_json` | string | yes | JSON string of the receipt envelope |

### `gateway_get_chain_stats`

Returns total receipts, approval/denial counts, Merkle root, and policy version. No parameters.

### `gateway_get_receipt_chain`

Returns all signed receipts in sequence order with hash chain linkage. No parameters.

### `gateway_get_public_key`

Returns the gateway's Ed25519 signing public key as a JWK. No parameters.

---

## Auditor Tools (3)

Query and trigger compliance audits powered by Gemini 2.5 Pro + RAG over OWASP/NIST PDFs.

### `auditor_query_audits`

Query compliance audit reports. Each report contains a verdict (ALIGNED/CONFLICT/INSUFFICIENT_EVIDENCE/ERROR), rationale, and verbatim citations.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tenant` | string | no | Tenant identifier (default: "default") |
| `since_seq` | integer | no | Only return reports for receipts with seq > this value |
| `limit` | integer | no | Maximum reports to return (max 200) |

### `auditor_audit_receipt`

Trigger an on-demand compliance audit of a specific receipt. Invokes Gemini 2.5 Pro (10-30s latency). Returns a signed audit report.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tenant` | string | yes | Tenant identifier |
| `receipt_seq` | integer | yes | Sequence number of the receipt to audit |

### `auditor_explain_verdict`

Retrieve a specific audit report by ID with full rationale and citations.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tenant` | string | yes | Tenant identifier |
| `audit_id` | string | yes | UUID of the audit report |

---

## Recommender Tools (3)

Query and trigger policy change proposals powered by Gemini 2.5 Pro.

### `recommender_query_proposals`

Query policy change proposals. Each proposal contains a trigger pattern, policy diff, confidence level, rationale, and supporting citations.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tenant` | string | no | Tenant identifier (default: "default") |
| `limit` | integer | no | Maximum proposals to return (max 100) |

### `recommender_explain_proposal`

Retrieve a specific policy proposal by ID with full rationale and diff.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tenant` | string | yes | Tenant identifier |
| `proposal_id` | string | yes | UUID of the policy proposal |

### `recommender_analyze_patterns`

Trigger on-demand analysis of recent audit patterns. Invokes Gemini 2.5 Pro (30-60s latency). Returns raw proposals (possibly empty).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tenant` | string | no | Tenant identifier (default: "default") |
| `window_hours` | integer | no | Hours of audit history to analyze (default 24) |

---

## Investigator Tools (3)

Query and trigger security incident investigations powered by Gemini 2.5 Pro.

### `investigator_query_incidents`

Query incident reports. Each report contains severity, executive summary, chronological timeline with evidence references, agents involved, compliance impact, root cause hypothesis, and recommended actions.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tenant` | string | no | Tenant identifier (default: "default") |
| `limit` | integer | no | Maximum incidents to return (max 100) |

### `investigator_investigate_conflict`

Trigger an on-demand investigation of a CONFLICT audit report. Invokes Gemini 2.5 Pro (30-90s latency). The Investigator cross-references receipts, audit reports, and agent registrations.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tenant` | string | yes | Tenant identifier |
| `audit_report_id` | string | yes | UUID of the CONFLICT audit report to investigate |

### `investigator_explain_incident`

Retrieve a specific incident report by ID with full narrative, timeline, and recommendations.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tenant` | string | yes | Tenant identifier |
| `incident_id` | string | yes | UUID of the incident report |

---

## Coordinator Tools (3)

Agent discovery and capability routing powered by Gemini 2.5 Pro.

### `coordinator_route_capability`

Route a natural-language question to the most capable agent. Returns matches with confidence scores. The Coordinator does NOT execute calls -- it only identifies the right agent.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `question` | string | yes | Natural-language description of what you need done |

### `coordinator_list_known_agents`

List all agents in the directory with name, URL, trust level, health status, and capabilities. No parameters.

### `coordinator_register_known_agent`

Register a new agent by its A2A agent card URL. The Coordinator fetches the card, assesses capabilities via Gemini, and adds it to the directory.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent_card_url` | string | yes | URL of the agent's A2A agent card |

---

## Backward-Compatibility Aliases (5)

These aliases preserve the original tool names for existing MCP clients:

| Alias | Delegates to |
|-------|-------------|
| `authorize_action` | `gateway_authorize_action` |
| `verify_receipt` | `gateway_verify_receipt` |
| `get_chain_stats` | `gateway_get_chain_stats` |
| `get_receipt_chain` | `gateway_get_receipt_chain` |
| `get_public_key` | `gateway_get_public_key` |

`register_agent` was removed from MCP to enforce proof of possession. Use the REST API for agent registration.
