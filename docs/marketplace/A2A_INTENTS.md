# Agent-to-Agent Protocol Intents

## Overview

Gate is A2A-native. The Gateway publishes an A2A agent card and exposes four skills via the Google A2A SDK (v1.1.0). Other agents in the ecosystem (Auditor, Recommender, Investigator, Coordinator) expose REST APIs but do not currently publish A2A agent cards — their integration into the A2A protocol surface is a v1.0 roadmap item.

This document enumerates every skill and endpoint across all five agents, their input/output schemas, and the authentication requirements for each.

## Agent Cards

| Agent | A2A Card | Status |
|---|---|---|
| Gateway | `https://agent-auth-gateway-a2a-1031148889398.us-central1.run.app/.well-known/agent-card.json` | Live |
| Auditor | — | REST-only (v1.0 roadmap) |
| Recommender | — | REST-only (v1.0 roadmap) |
| Investigator | — | REST-only (v1.0 roadmap) |
| Coordinator | — | REST-only (v1.0 roadmap) |

The Gateway's agent card declares version `0.4.0`, supports text input/output modes, and lists four skills.

## Gateway Skills (A2A)

Callers send JSON-encoded messages to the A2A surface. The message format is:

```json
{"skill": "<skill_id>", "input": { ... }}
```

The response is a JSON object in a text part of the A2A Task completion message.

### authorize_action

Issue a short-lived Ed25519 token authorizing a specific action by a registered agent. Requires a DPoP proof.

**Input schema:**

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_id` | string | Yes | Unique identifier of the requesting agent |
| `action` | string | Yes | The intended action (e.g., `read`, `query`, `delete`) |
| `resource` | string | Yes | Target resource identifier |
| `agent_proof` | string | Yes | DPoP-style JWT signed by the agent's Ed25519 private key |
| `parameters` | object | No | Action-specific parameters |

**Output schema:**

| Field | Type | Description |
|---|---|---|
| `decision` | string | `approve` or `deny` |
| `reason_codes` | string[] | Policy rule identifiers that caused denial (empty on approve) |
| `token` | string | Ed25519-signed JWT (present only on approve; 60-second TTL) |
| `receipt_hash` | string | SHA-256 hash of the signed receipt (`sha256:...`) |
| `action_digest` | string | SHA-256 hash of the canonicalized action intent |

**Error conditions:**

| Error Code | Meaning | HTTP-equivalent |
|---|---|---|
| `NO_PROOF` | `agent_proof` not provided | 400 |
| `UNREGISTERED_AGENT` | Agent's public key not found in registry | 401 |
| `PROOF_SIGNATURE_INVALID` | DPoP JWT signature verification failed | 401 |
| `PROOF_EXPIRED` | DPoP JWT timestamp outside 30-second freshness window | 401 |
| `PROOF_REPLAY` | DPoP JWT JTI has been seen before | 401 |
| `PROOF_DIGEST_MISSING` | DPoP JWT missing `action_digest` claim | 400 |
| `PROOF_DIGEST_MISMATCH` | `action_digest` in proof does not match computed digest | 400 |

**Example request:**

```json
{
  "skill": "authorize_action",
  "input": {
    "agent_id": "worker-analytics-01",
    "action": "read",
    "resource": "staging-database",
    "agent_proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiLi4uIn19.eyJqdGkiOiJ1dWlkIiwiYWdlbnRfaWQiOiJ3b3JrZXItYW5hbHl0aWNzLTAxIiwiYWN0aW9uX2RpZ2VzdCI6InNoYTI1NjouLi4iLCJpYXQiOjE3MTcwMDAwMDB9.c2lnbmF0dXJl"
  }
}
```

**Example response (approved):**

```json
{
  "decision": "approve",
  "reason_codes": [],
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImdhdGV3YXktaGFja2F0aG9uLWRlbW8tZDdjZmNjYzkifQ...",
  "receipt_hash": "sha256:a1b2c3d4e5f6...",
  "action_digest": "sha256:9f8e7d6c5b4a..."
}
```

### verify_receipt

Verify the cryptographic integrity of a receipt, including Ed25519 signature validation and single-step chain linkage (prev_receipt hash check).

**Input schema:**

| Field | Type | Required | Description |
|---|---|---|---|
| `receipt_seq` | string | Yes | Sequence number of the receipt to verify |

**Output schema:**

| Field | Type | Description |
|---|---|---|
| `signature_validity` | string | `PASS` or `FAIL` |
| `chain_validity` | string | `PASS`, `FAIL`, or `INCONCLUSIVE` |
| `detail` | string | Human-readable verification summary |
| `errors` | string[] | List of specific verification failures |

**Error conditions:**

| Error Code | Meaning |
|---|---|
| `RECEIPT_NOT_FOUND` | No receipt exists at the given sequence number |

### get_public_key

Return the gateway's Ed25519 public key in JWK format. Used by clients to verify receipts and tokens offline.

**Input schema:** Empty object `{}`

**Output schema:**

| Field | Type | Description |
|---|---|---|
| `kty` | string | Always `OKP` |
| `crv` | string | Always `Ed25519` |
| `kid` | string | Key identifier (e.g., `gateway-hackathon-demo-d7cfccc9`) |
| `use` | string | `sig` |
| `alg` | string | `EdDSA` |
| `x` | string | Base64url-encoded public key bytes |

### get_chain_summary

Return receipt chain statistics including total count, latest sequence number, and Merkle root.

**Input schema:** Empty object `{}`

**Output schema:**

| Field | Type | Description |
|---|---|---|
| `total_requests` | integer | Total receipts in the chain |
| `approvals` | integer | Count of `approve` decisions |
| `denials` | integer | Count of `deny` decisions |
| `unique_agents` | integer | Distinct agent_ids seen |

## Auditor Endpoints (REST)

The Auditor exposes REST endpoints, not A2A skills.

### POST /audit-tick

Trigger a batch audit of unaudited receipts. Typically invoked by Cloud Scheduler.

**Input:** No request body required.

**Output:**

| Field | Type | Description |
|---|---|---|
| `audited` | integer | Receipts audited in this tick |
| `skipped` | integer | Receipts skipped |
| `errors` | integer | Processing errors |
| `by_verdict` | object | Counts per verdict: `{ALIGNED, CONFLICT, INSUFFICIENT_EVIDENCE, ERROR}` |

### GET /audit-reports

Query signed audit reports for a tenant.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `tenant` | string | Yes | Tenant identifier |
| `since_seq` | integer | No | Return reports for receipts above this sequence (default: 0) |
| `limit` | integer | No | Maximum reports to return (default: 50, max: 200) |

**Output:** `{reports: [{body: {audit_id, receipt_seq, verdict, rationale, citations, audited_at}, sig: {alg, kid, value}}]}`

### GET /audit-keys

Returns the Auditor's Ed25519 public key in JWK format.

## Recommender Endpoints (REST)

### POST /recommend-tick

Trigger policy recommendation analysis. Invoked by Cloud Scheduler hourly.

**Output:** `{tenants_processed: int, proposals_created: int, errors: int}`

### GET /proposals

Query signed policy proposals for a tenant.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `tenant` | string | Yes | Tenant identifier |
| `limit` | integer | No | Maximum proposals (default: 20, max: 100) |

**Output:** `{proposals: [{body: {proposal_id, trigger, proposed_change, confidence, proposed_at, human_review_required}, sig: {alg, kid, value}}]}`

### GET /recommender-keys

Returns the Recommender's Ed25519 public key in JWK format.

## Investigator Endpoints (REST)

### POST /investigate

Trigger an investigation. Accepts both Pub/Sub push format and direct HTTP.

**Direct input:**

| Field | Type | Required | Description |
|---|---|---|---|
| `tenant` | string | No | Tenant identifier (defaults to configured default) |
| `trigger.type` | string | Yes | `AUDIT_CONFLICT`, `POLICY_PROPOSAL`, or `MANUAL` |
| `trigger.trigger_id` | string | Yes | ID of the triggering artifact |

**Pub/Sub push input:** `{message: {data: "<base64-encoded JSON>"}}`

**Output:** `{incident_id: string, severity: string, tenant: string, trigger: object}`

### GET /incidents

Query signed incident reports for a tenant.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `tenant` | string | Yes | Tenant identifier |
| `limit` | integer | No | Maximum incidents (default: 20, max: 100) |

### GET /investigator-keys

Returns the Investigator's Ed25519 public key in JWK format.

## Coordinator Endpoints (REST)

### POST /discover

Register a new A2A agent by fetching and analyzing its agent card.

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_card_url` | string | Yes | URL of the agent's `/.well-known/agent-card.json` |
| `introducer` | string | No | Identifier of the agent or human introducing this entry |

**Output:** `{status, agent_card_url, trust_level, health_status, ai_assessed_capabilities}`

### POST /scan

Batch-scan a list of URLs for A2A-compatible agents.

| Field | Type | Required | Description |
|---|---|---|---|
| `urls` | string[] | Yes | List of URLs to scan |

### GET /directory

List all agents in the Coordinator's directory.

**Output:** `{agents: [{agent_card_url, agent_card, trust_level, health_status, ai_assessed_capabilities}], count: int}`

### POST /route-question

AI-powered capability matching. Given a natural-language question, returns the best-matching agent(s) from the directory.

| Field | Type | Required | Description |
|---|---|---|---|
| `question` | string | Yes | Natural-language capability query |

### GET /coordinator-keys

Returns the Coordinator's Ed25519 public key in JWK format.

## Authentication Patterns

### Layer 1: Transport Authentication

**MCP surface:** Bearer token in the `Authorization` header. Configured via `MCP_BEARER_TOKEN` environment variable. Mode controlled by `MCP_AUTH_MODE` (bearer, iam, or none — `none` requires `GATEWAY_DEV_MODE=true`).

**A2A surface:** OIDC token in the `Authorization` header, with audience set to the target service URL.

**REST surface:** No transport authentication. Security relies entirely on Layer 2 (DPoP).

**AI agent surfaces (Auditor, Recommender, Investigator, Coordinator):** Cloud Run IAM (`allUsers` for demo; restrict to specific service accounts in production).

### Layer 2: DPoP Proof of Possession

Required for `authorize_action` only. Every authorization request must include a fresh DPoP proof JWT with:

- **Header:** `{"alg": "EdDSA", "typ": "dpop+jwt", "jwk": {<agent's public JWK>}}`
- **Payload:** `{"jti": "<UUID>", "agent_id": "<id>", "action_digest": "sha256:<hex>", "iat": <unix_timestamp>}`
- **Signature:** Ed25519 signature over `base64url(header).base64url(payload)`

The `action_digest` is the SHA-256 hash of the JCS-canonicalized action intent (see [docs/protocol.md](../protocol.md) for the worked examples).

Freshness window: 30 seconds. JTI replay prevention: in-memory cache per gateway instance.

## Conformance Requirements

Agents that interoperate with Gate must:

1. **Generate an Ed25519 keypair** (one-time) and register the public key with the Gateway via `register_agent` (MCP) or the two-step `POST /agents/register-challenge` + `POST /agents/register` flow (REST). REST registration requires proof of possession — the registrant must sign a challenge nonce with the corresponding private key.
2. **Produce DPoP proofs** per the profile documented in [docs/protocol.md](../protocol.md) for every `authorize_action` call. The `action_digest` must be computed using RFC 8785 JCS canonicalization.
3. **Verify Gate's signed responses** using Gate's published public keys from `/keys` or `get_public_key`.
4. **Handle token error conditions:** expired (60-second TTL), wrong audience, action_digest mismatch, and replay (JTI reuse).

An independent reference implementation exists at `github.com/4KInc/agent-authorization-gateway` in the `independent-agent/` directory, demonstrating full protocol conformance without importing any gateway code.

## Versioning

Current agent card version: **0.4.0**. The protocol version is declared in the agent card's `version` field and in the receipt body's `v` field (currently `"1"`). Backward compatibility guarantees are documented in [docs/protocol.md](../protocol.md).
