# Agent Authorization Gateway — System Guide

How agents are registered, how policies are defined, how resources are
protected, and how the full authorize-then-execute flow works end to end.

---

## Table of Contents

1. [Concepts](#1-concepts)
2. [Agent Onboarding](#2-agent-onboarding)
3. [Policy Definition](#3-policy-definition)
4. [Resource Definition](#4-resource-definition)
5. [The Authorization Flow](#5-the-authorization-flow)
6. [Token Lifecycle](#6-token-lifecycle)
7. [Receipt Chain & Tamper Evidence](#7-receipt-chain--tamper-evidence)
8. [Verification & Audit](#8-verification--audit)
9. [Multi-Agent Ecosystem](#9-multi-agent-ecosystem)
10. [File Reference](#10-file-reference)

---

## 1. Concepts

The Gateway controls what AI agents can do. Every request follows
this pipeline:

```
Agent registers identity (once)
        |
Agent signs DPoP proof (per request)
        |
Gateway verifies proof -> evaluates policy -> signs receipt -> issues token
        |
Agent uses token at Protected Resource
        |
Resource verifies token with Gateway's public key
```

There are no shared secrets anywhere. Every cryptographic operation
uses Ed25519 (EdDSA, RFC 8037). Tokens are short-lived (60 seconds),
single-use, and bound to a specific action + resource.

### Key Terminology

| Term | Meaning |
|------|---------|
| **Agent** | An AI worker (non-human identity) that wants to perform actions |
| **Action** | What the agent wants to do: `read`, `query`, `delete`, etc. |
| **Resource** | What the agent wants to act on: `staging-database`, `customers`, etc. |
| **DPoP Proof** | A signed JWT proving the agent holds its private key |
| **Token** | A 60-second Ed25519-signed JWT authorizing a specific action |
| **Receipt** | A signed, hash-chained record of the authorization decision |
| **Policy** | A set of rules defining what actions/resources are allowed |

---

## 2. Agent Onboarding

### 2.1 Generate an Identity Keypair

Every agent starts by generating an Ed25519 keypair. The private key
stays with the agent; the public key is registered with the Gateway.

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64

agent_key = Ed25519PrivateKey.generate()
pub_bytes = agent_key.public_key().public_bytes_raw()
jwk = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()
}
```

### 2.2 Register with the Gateway (Two-Step Proof-of-Possession)

Registration is a two-step flow that proves the agent holds its private key before the public key is accepted.

**Step 1 — Get a challenge nonce**

**Endpoint:** `POST /agents/register-challenge`

```json
{ "agent_id": "my-worker-01" }
```

**Response:**
```json
{
  "nonce": "a7f3c2...",
  "expires_in": 60
}
```

The nonce is single-use and expires after 60 seconds.

**Step 2 — Submit registration with signed proof**

**Endpoint:** `POST /agents/register`

```json
{
  "agent_id": "my-worker-01",
  "public_key": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "<base64url-encoded-32-byte-public-key>"
  },
  "registration_proof": "<EdDSA JWT signed over the nonce with the agent's private key>"
}
```

The `registration_proof` is a JWT whose payload contains `{"sub": "my-worker-01", "nonce": "<nonce>", "iat": <unix_ts>}`, signed with the agent's Ed25519 private key. The Gateway verifies the signature against the submitted JWK before completing registration.

**Response:**
```json
{
  "status": "registered",
  "agent_id": "my-worker-01",
  "kid": "agent-3aaa21d5e363b7c0"
}
```

**What happens internally:**

1. **Validate agent_id** — must match `[a-zA-Z0-9_-]{1,256}`
2. **Validate JWK** — `kty` must be `OKP`, `crv` must be `Ed25519`, `x` must decode to exactly 32 bytes
3. **Verify nonce** — nonce must be valid, unused, and within the 60-second TTL; consumed on use
4. **Verify registration proof** — Ed25519 signature over the nonce must verify against the submitted public key
5. **Compute key fingerprint (kid)** — `"agent-" + sha256(raw_key_bytes)[:16]`
6. **Replace semantics** — re-registering the same `agent_id` replaces the existing key (no HTTP 409)
7. **Persist to Firestore** at `tenants/{tenant}/agent_registry/{agent_id}`
8. **Update in-memory cache** — two maps: by `agent_id` and by `kid`

Source: `gateway/identity.py:147-197` (AgentRegistry.register)

### 2.3 Agent ID Rules

- 1-256 characters
- Alphanumeric, hyphens, underscores only: `[a-zA-Z0-9_-]`
- Case-sensitive: `Worker-01` and `worker-01` are different agents
- Must be unique per tenant

### 2.4 Revocation

**Endpoint:** `DELETE /agents/{agent_id}`

Revoked agents cannot authorize new actions. The registration record
is kept in Firestore for audit (status changes from `active` to `revoked`).
Revocation is immediate — the in-memory cache is updated synchronously.

### 2.5 Listing Registered Agents

**Endpoint:** `GET /agents?include_revoked=false`

Returns all active (or all, if `include_revoked=true`) agent registrations
with their `agent_id`, `kid`, `registered_at`, and `status`.

---

## 3. Policy Definition

### 3.1 Policy Structure

A policy is a versioned list of rules. ALL rules must pass for an action
to be approved — any single rule failure means denial.

```yaml
# policy.yaml
version: "1"
rules:
  - id: allowed_actions
    type: allowlist
    config:
      allowed_actions:
        - read
        - query
        - list
        - get
        - search
        - analyze

  - id: resource_scope
    type: resource_scope
    config:
      allowed_resources:
        - staging
        - dev
        - sandbox
        - test
      denied_resources:
        - production
        - prod
        - master-key
        - admin

  - id: rate_limit
    type: rate_limit
    config:
      max_actions: 10
      window_seconds: 60
```

### 3.2 Rule Types

#### Action Allowlist (`type: allowlist`)

Controls which actions are permitted. The agent's requested action must
exactly match (case-insensitive) one of the allowed actions.

| Field | Type | Meaning |
|-------|------|---------|
| `allowed_actions` | `list[str]` | Actions that are permitted. Empty list = allow all. |

Examples:
- Agent requests `read` and policy allows `[read, query]` — **APPROVE**
- Agent requests `delete` and policy allows `[read, query]` — **DENY** with `ACTION_NOT_ALLOWED:allowed_actions`

#### Resource Scope (`type: resource_scope`)

Controls which resources agents can access. Uses **substring matching**
(case-insensitive). The denied list is checked first.

| Field | Type | Meaning |
|-------|------|---------|
| `allowed_resources` | `list[str]` | Substrings that must appear in the resource name |
| `denied_resources` | `list[str]` | Substrings that block access if found in the resource name |

Examples:
- Resource `staging-database` contains `staging` (allowed) and does not contain any denied term — **APPROVE**
- Resource `production-db` contains `production` (denied) — **DENY** with `RESOURCE_OUT_OF_SCOPE:resource_scope`
- Resource `admin-panel` contains `admin` (denied) — **DENY**

**Deny takes priority.** If a resource matches both an allowed and a denied
substring, it is denied.

#### Rate Limit (`type: rate_limit`)

Limits how many actions a single agent can perform within a sliding window.
Counters are per-agent-per-rule, persisted to Firestore across restarts.

| Field | Type | Meaning |
|-------|------|---------|
| `max_actions` | `int` | Maximum actions allowed in the window |
| `window_seconds` | `int` | Sliding window duration in seconds |

Example: With `max_actions: 10` and `window_seconds: 60`, an agent that
has made 10 requests in the last minute will be denied with
`RATE_LIMIT_EXCEEDED:rate_limit`.

### 3.3 Loading Policy

The Gateway loads policy in priority order:

1. **YAML file** — if `POLICY_YAML_PATH` env var is set, load from that path on disk
2. **Firestore** — if a policy document exists at `tenants/{tenant}/policy/active`
3. **Built-in demo policy** — the default (read-only, staging resources, 10/min rate limit)

Loading failures are fatal — the Gateway will not start with a broken policy.

### 3.3.1 `require_resource_registration` Flag

Policies may include the optional flag `require_resource_registration: true` at the top level. When set, the Gateway rejects authorization requests for resources that have not been explicitly registered via `POST /resources`. This provides an explicit allowlist at the resource level, layered on top of the substring-matching `resource_scope` rule.

```yaml
version: "1"
require_resource_registration: true
rules:
  - id: allowed_actions
    type: allowlist
    config:
      allowed_actions: [read, query]
```

When `require_resource_registration` is `false` (default), resources do not need to be pre-registered and are matched purely by the `resource_scope` rule.

### 3.4 Updating Policy at Runtime

**Endpoint:** `PUT /policy`

```json
{
  "version": "2",
  "rules": [
    {
      "id": "strict_read_only",
      "type": "allowlist",
      "config": {"allowed_actions": ["read", "list"]}
    }
  ]
}
```

This updates both the in-memory policy and persists it to Firestore.
The new policy takes effect immediately for all subsequent authorization
requests. The old policy remains in the receipt chain — each receipt
records the `policy_version` (SHA-256 hash) that was active at decision time.

### 3.5 Dry-Run

**Endpoint:** `POST /authorize/dry-run`

Evaluates the policy without creating a receipt or issuing a token. Useful
for testing policy changes before applying them.

### 3.6 Policy Hash Binding

Every receipt includes a `policy_version` field containing the SHA-256
hash of the canonicalized policy that was active at decision time. This
means you can always prove which policy was in effect for any given
authorization decision — even after the policy has been updated.

### 3.7 Example Policies

The repo includes three example policies in `examples/`:

| File | Description |
|------|-------------|
| `policy-strict.json` | Read-only actions, staging/dev/sandbox resources only |
| `policy-permissive.json` | All actions including write/deploy, only denies secrets/root |
| `policy-readonly.json` | Minimal read-only (read, list, get, search) |

---

## 4. Resource Definition

### 4.1 Resources Are Not Pre-Defined

Unlike agents (which must be registered) and policies (which are explicit
YAML rules), **resources are not defined ahead of time**. A resource is
simply a string that the agent provides when requesting authorization:

```json
{
  "agent_id": "worker-01",
  "action": "read",
  "resource": "staging-database"
}
```

The resource string `"staging-database"` is evaluated against the policy's
resource scope rules via substring matching. There is no resource registry
or resource catalog.

### 4.2 How Resource Matching Works

The policy's `resource_scope` rule uses **case-insensitive substring matching**:

```python
resource_lower = resource.lower()

# Step 1: Check denied list (deny takes priority)
if any(denied_term in resource_lower for denied_term in denied_resources):
    return DENY

# Step 2: Check allowed list
if allowed_resources:
    return any(allowed_term in resource_lower for allowed_term in allowed_resources)
```

This means:
- `"staging-database"` matches allowed `"staging"` — approved
- `"staging-prod-mirror"` matches denied `"prod"` — denied (deny takes priority)
- `"my-custom-service"` does not match any allowed term — denied

### 4.3 Protecting a Resource Endpoint

A resource server (any API) protects its endpoints using the Gateway
middleware. The middleware verifies the token without needing access to
the Gateway's private key — it only needs the public key (fetched from
`GET /keys`).

```python
from gateway.middleware import require_gateway_token

@app.get("/customers/{customer_id}")
async def read_customer(
    customer_id: str,
    claims=Depends(require_gateway_token("read", "staging-database")),
):
    return {"customer": ..., "authorized_by": claims["sub"]}
```

The middleware enforces:

| Check | Error Code | Description |
|-------|------------|-------------|
| Token present | `NO_TOKEN` | `Authorization: Bearer <token>` header required |
| Signature valid | `INVALID_SIGNATURE` | Ed25519 verification against Gateway's public key |
| Not expired | `EXPIRED` | Token TTL is 60 seconds (+5s clock skew) |
| Not replayed | `REPLAY` | JTI tracked in replay cache (10,000 entries) |
| Action matches | `WRONG_ACTION` | Token's `action` must match endpoint's expected action |
| Resource matches | `WRONG_RESOURCE` | Token's `resource` must match (bidirectional substring) |

### 4.4 Resource-Action Binding

The token is cryptographically bound to a specific action + resource
via the `action_digest` claim (SHA-256 of the canonicalized intent).
A token issued for `read` on `staging-database` cannot be used for
`delete` on `staging-database` or `read` on `production-db`.

### 4.5 Example Protected Resource

See `examples/protected_resource/main.py` — a demo customer API with
three endpoints:

| Endpoint | Required Action | Required Resource |
|----------|-----------------|-------------------|
| `GET /customers/{id}` | `read` | `staging-database` |
| `POST /customers` | `query` | `staging-database` |
| `DELETE /customers/{id}` | `delete` | `staging-database` |

---

## 5. The Authorization Flow

### 5.1 Step-by-Step

```
  Agent                          Gateway                    Protected Resource
    |                              |                              |
    |  1. POST /agents/register    |                              |
    |  {agent_id, public_key}      |                              |
    |----------------------------->|                              |
    |  {status: registered, kid}   |                              |
    |<-----------------------------|                              |
    |                              |                              |
    |  2. Sign DPoP proof          |                              |
    |  (agent's private key)       |                              |
    |                              |                              |
    |  3. POST /authorize          |                              |
    |  {agent_id, action,          |                              |
    |   resource, agent_proof}     |                              |
    |----------------------------->|                              |
    |                              |  a. Verify DPoP proof        |
    |                              |  b. Evaluate policy          |
    |                              |  c. Sign receipt             |
    |                              |  d. Issue token (if approve) |
    |  {decision, token, receipt}  |                              |
    |<-----------------------------|                              |
    |                              |                              |
    |  4. GET /customers/c1                                       |
    |  Authorization: Bearer <token>                              |
    |------------------------------------------------------------>|
    |                              |  e. Fetch Gateway public key |
    |                              |<-----------------------------|
    |                              |  {keys: [{kid, x, ...}]}     |
    |                              |----------------------------->|
    |                              |  f. Verify token signature   |
    |                              |  g. Check action/resource    |
    |                              |  h. Check JTI replay         |
    |  {customer data}                                            |
    |<------------------------------------------------------------|
```

### 5.2 DPoP Proof (Step 2)

Before every authorization request, the agent signs a proof JWT with
its own private key. This proves the agent holds the key it registered.

**Proof payload:**
```json
{
  "sub": "my-worker-01",
  "htm": "POST",
  "htu": "agent-authorization-gateway",
  "action": "read",
  "resource": "staging-database",
  "jti": "<uuid>",
  "iat": 1779987015,
  "action_digest": "sha256:<hex>"
}
```

The `action_digest` is the SHA-256 of the canonicalized intent
(`agent_id + action + resource + parameters`). This binds the proof
to the exact request, preventing cross-action replay.

Source: `gateway/identity.py:250-283` (create_agent_proof)

### 5.3 Proof Verification (Step 3a)

The Gateway verifies the proof in strict order. Failure at any step
returns a specific error code:

| Order | Check | Error Code |
|-------|-------|------------|
| 1 | Proof is present | `NO_PROOF` |
| 2 | JWT is parseable | `INVALID_PROOF` |
| 3 | `sub` matches `agent_id` | `AGENT_MISMATCH` |
| 4 | Agent is registered | `UNREGISTERED_AGENT` |
| 5 | Ed25519 signature is valid | `INVALID_PROOF_SIGNATURE` |
| 6 | `iat` within 30 seconds | `PROOF_EXPIRED` |
| 7 | `action` matches request | `PROOF_ACTION_MISMATCH` |
| 8 | `resource` matches request | `PROOF_RESOURCE_MISMATCH` |
| 9 | `action_digest` is present | `PROOF_DIGEST_MISSING` |
| 10 | `action_digest` matches computed | `PROOF_DIGEST_MISMATCH` |
| 11 | `jti` not replayed | `PROOF_REPLAY` |

Source: `gateway/identity.py:286-365` (verify_agent_proof)

### 5.4 Policy Evaluation (Step 3b)

After proof verification, the Gateway evaluates the request against
all policy rules. ALL rules must pass. See [Section 3](#3-policy-definition).

### 5.5 Authorization Response

```json
{
  "decision": "approve",
  "reason_codes": [],
  "token": "eyJ...",
  "receipt": {
    "body": {
      "v": "1",
      "tenant": "hackathon-demo",
      "seq": "42",
      "ts": "2026-05-30T15:42:00.123Z",
      "request_digest": "sha256:...",
      "policy_version": "sha256:...",
      "decision": "approve",
      "reasons": [],
      "prev_receipt": "sha256:...",
      "token_jti": "a1b2c3d4-..."
    },
    "sig": {
      "alg": "EdDSA",
      "kid": "gateway-tenant-hexid",
      "value": "<base64url-signature>"
    },
    "receipt_hash": "sha256:..."
  },
  "action_digest": "sha256:...",
  "receipt_hash": "sha256:..."
}
```

For **denials**, `token` is `null` and `reason_codes` contains the
specific denial reasons (e.g., `["ACTION_NOT_ALLOWED:allowed_actions"]`).
A receipt is still signed for every denial — denials are part of the
audit trail.

---

## 6. Token Lifecycle

### 6.1 Token Structure

The token is an Ed25519-signed JWT (EdDSA algorithm):

```json
{
  "iss": "agent-authorization-gateway",
  "aud": "protected-resource",
  "sub": "my-worker-01",
  "tid": "hackathon-demo",
  "action": "read",
  "resource": "staging-database",
  "action_digest": "sha256:...",
  "decision": "approve",
  "receipt_hash": "sha256:...",
  "jti": "a1b2c3d4-...",
  "iat": 1779987015,
  "exp": 1779987075
}
```

### 6.2 Token Properties

| Property | Value | Purpose |
|----------|-------|---------|
| TTL | 60 seconds | Limits exposure window |
| Algorithm | EdDSA (Ed25519) | Asymmetric — no shared secrets |
| Single-use | JTI replay cache | Prevents token reuse |
| Action-bound | `action` + `action_digest` | Cannot be used for different actions |
| Resource-bound | `resource` | Cannot be used on different resources |
| Receipt-bound | `receipt_hash` | Links token to its audit trail |
| Issuer | `agent-authorization-gateway` | Verified by middleware |
| Audience | `protected-resource` | Verified by middleware |

### 6.3 Token Verification at Resources

Resources verify tokens using only the Gateway's **public key** (fetched
from `GET /keys` with 5-minute TTL caching). No shared secret is needed.

The middleware supports key rotation — it tries all keys returned by
the Gateway and accepts the first one that produces a valid signature.

### 6.4 What Cannot Be Done With a Token

- **Cannot be forged** — requires the Gateway's Ed25519 private key
- **Cannot be replayed** — JTI is tracked in the replay cache
- **Cannot be used after expiry** — 60-second TTL enforced
- **Cannot be used for wrong action** — action claim is verified
- **Cannot be used on wrong resource** — resource claim is verified
- **Cannot be transferred** — bound to agent_id via `sub` claim

---

## 7. Receipt Chain & Tamper Evidence

### 7.1 Receipt Structure

Every authorization decision (approve AND deny) produces a signed receipt:

```
Receipt Body (7 fields + optional token_jti):
  v              — version ("1")
  tenant         — tenant ID
  seq            — monotonic sequence number
  ts             — ISO 8601 timestamp
  request_digest — SHA-256 of canonicalized intent
  policy_version — SHA-256 hash of active policy
  decision       — "approve" or "deny"
  reasons        — array of denial reason codes (empty for approve)
  prev_receipt   — hash of the previous receipt (chain linkage)
  token_jti      — JTI of issued token (null for deny)
```

### 7.2 Signing Process

1. **Canonicalize** the receipt body using JCS (RFC 8785 subset)
2. **Compute hash** — `sha256:` + SHA-256 of canonical bytes
3. **Sign** — Ed25519 signature of the canonical bytes
4. **Advance chain** — set `prev_receipt_hash = receipt_hash` for next receipt

### 7.3 Hash Chain

Each receipt points to the previous receipt via `prev_receipt`. The
first receipt points to the genesis hash (`sha256:` + 64 zeros). This
forms a tamper-evident chain: modifying any receipt breaks the hash
linkage for all subsequent receipts.

```
Receipt #1                Receipt #2                Receipt #3
prev: genesis  --------> prev: hash(#1) --------> prev: hash(#2)
hash: abc123              hash: def456              hash: ghi789
```

### 7.4 Merkle Anchoring

Receipt hashes are batched into a Merkle tree. The Merkle root is
anchored to:

- **Local JSONL file** — append-only, each entry signed
- **Google Cloud Storage** — versioned objects
- **Base L2 mainnet** — on-chain calldata at a burn address

Anchoring schedule: every 10 receipts or every hour, whichever comes first.

### 7.5 Firestore Persistence

Every receipt is persisted to Firestore immediately after signing:

```
tenants/{tenant}/receipts/{seq}
  body: { v, tenant, seq, ts, request_digest, ... }
  sig: { alg, kid, value }
  receipt_hash: "sha256:..."
  _meta: { agent_id, action, resource, parameters }
```

The `_meta` field stores the original request parameters for display
purposes — the receipt body itself only stores the `request_digest`
(SHA-256 of the intent), keeping the signed body minimal.

---

## 8. Verification & Audit

### 8.1 Receipt Verification

**Endpoint:** `GET /verify-receipt/{seq}` or programmatically via
`gateway/verify.py`

Anyone with the Gateway's public key can verify a receipt:

1. **Canonicalize** the receipt body
2. **Recompute hash** — compare against claimed `receipt_hash`
3. **Verify signature** — Ed25519 verification with public key
4. **Check chain linkage** — `prev_receipt` matches predecessor's hash

```json
{
  "receipt_integrity": "PASS",
  "chain_validity": "PASS",
  "errors": []
}
```

### 8.2 Full Chain Verification

**Endpoint:** `GET /verify-chain`

Verifies the entire receipt chain:
- All signatures are valid
- Sequence numbers are monotonic and dense (1, 2, 3, ...)
- `prev_receipt` hashes form an unbroken chain from genesis
- No gaps, no duplicates, no reordering

### 8.3 Tamper Detection

If any receipt body field is modified after signing:
- `RECEIPT_HASH_MISMATCH` — the recomputed hash differs from the claimed hash
- `SIGNATURE_INVALID` — the Ed25519 signature no longer matches

If a receipt is removed or reordered:
- `SEQUENCE_GAP` — missing sequence number
- `CHAIN_BREAK` — `prev_receipt` link is broken

### 8.4 Policy Auditor Agent

An automated Gemini 2.5 Pro agent that audits every receipt against
compliance frameworks (NIST SP 800-53, OWASP NHI Top 10). Produces
signed audit reports stored in Firestore. See `gateway/auditor/`.

### 8.5 Investigation Agent

Triggered by audit conflicts. Synthesizes evidence from multiple
sources (receipts, audit reports, agent registrations) into
incident reports. See `gateway/investigator/`.

### 8.6 Policy Recommendation Agent

Analyzes patterns across audit reports and proposes policy changes
for human review. Never modifies policy directly. See
`gateway/recommender/`.

---

## 9. Multi-Agent Ecosystem

### 9.1 Agent Surfaces

The Gateway exposes four protocol surfaces:

| Surface | URL Pattern | Use Case |
|---------|-------------|----------|
| REST | `/authorize`, `/agents/register`, etc. | Direct HTTP integration |
| MCP | `/mcp` | Claude, Cursor, and other MCP-enabled AI tools |
| ADK | Google ADK agent | Agent-to-agent via Google's Agent Development Kit |
| A2A | `/.well-known/agent.json` | A2A protocol interop |

All four surfaces call the same `GatewayService.authorize()` — the
single cryptographic chokepoint. No surface can bypass proof verification.

A2A support is not a separate service. Each agent's REST service exposes
its own `/.well-known/agent.json` agent card, making every agent
directly discoverable and callable via the A2A protocol without an
additional sidecar or gateway.

### 9.2 Isolator Agent

The Isolator is the sixth agent in the ecosystem. It performs automated
containment when the Investigation Agent raises a HIGH or CRITICAL
severity incident.

**Trigger:** HIGH or CRITICAL incident messages on the `agent-incidents`
Pub/Sub topic, published by the Investigation Agent.

**Actions on trigger:**

1. **Revoke agent registration** — calls `DELETE /agents/{agent_id}` to
   immediately invalidate the offending agent's ability to authorize new
   actions
2. **Rate limit to zero** — pushes a policy update that sets
   `max_actions: 0` for the affected agent (belt-and-suspenders in case
   revocation is delayed)
3. **Produce signed containment record** — signs a containment receipt
   (same Ed25519/JCS scheme as authorization receipts) and stores it at
   `tenants/{tenant}/containment/{incident_id}`

Containment is automated and does not require human approval. A human
operator can reverse containment by restoring the agent's registration
and resetting the rate limit via the REST API.

See `gateway/isolator/`.

### 9.3 Discovery Coordinator

The Discovery Coordinator maintains a directory of A2A agents in the
environment and provides Gemini-powered capability matching:

- **POST /discover** — register a new A2A agent by its agent card URL
- **POST /scan** — scan multiple URLs for A2A agents
- **GET /directory** — list all known agents
- **POST /route-question** — "I need an agent that can do X. Which one matches?"

See `gateway/coordinator/`.

### 9.4 Tenant Isolation

All data is scoped by tenant. The tenant ID is embedded in every
receipt, token, and Firestore path. Different tenants have independent
agent registries, receipt chains, policies, and rate limits.

---

## 10. File Reference

### Core Gateway

| File | Purpose |
|------|---------|
| `gateway/gateway_service.py` | Authorization chokepoint — orchestrates proof, policy, receipt, token |
| `gateway/policy.py` | PolicyEngine — evaluates allowlist, resource_scope, rate_limit rules |
| `gateway/identity.py` | AgentRegistry + DPoP proof creation/verification |
| `gateway/tokens.py` | Token issuance (Ed25519-signed JWT) + action digest |
| `gateway/receipts.py` | Receipt signing + hash chain management |
| `gateway/middleware.py` | Resource-side token verification (FastAPI dependency) |
| `gateway/verify.py` | Independent receipt and chain verification |
| `gateway/canonical.py` | JCS canonicalization (RFC 8785 subset) |
| `gateway/api.py` | REST API endpoints |
| `gateway/mcp_server.py` | MCP protocol server |

### Policy Files

| File | Purpose |
|------|---------|
| `policy.yaml` | Active policy (loaded if `POLICY_YAML_PATH` is set) |
| `examples/policy-strict.json` | Example: read-only, staging only |
| `examples/policy-permissive.json` | Example: all actions, only denies secrets |
| `examples/policy-readonly.json` | Example: minimal read-only |

### Demo Scripts

| File | Purpose |
|------|---------|
| `examples/demo/demo_compliant_worker.py` | Full happy-path: register, authorize, use token, deny |
| `examples/demo/demo_rogue_worker.py` | Attack scenarios: no token, forged token, expired, wrong action |
| `examples/demo/demo_tamper.py` | Tamper detection: modifies a receipt, verifies chain catches it |
| `examples/demo/run_demo.sh` | Orchestrates all demos, exits non-zero on failure |

### Agent Services

| Directory | Agent | Purpose |
|-----------|-------|---------|
| `gateway/auditor/` | Policy Auditor | Audits receipts against compliance frameworks |
| `gateway/recommender/` | Policy Recommender | Proposes policy changes based on audit patterns |
| `gateway/investigator/` | Investigation Agent | Deep-dives into audit conflicts |
| `gateway/coordinator/` | Discovery Coordinator | A2A agent directory + capability routing |
| `gateway/isolator/` | Isolator | Automated containment on HIGH/CRITICAL incidents |

### Protected Resource Example

| File | Purpose |
|------|---------|
| `examples/protected_resource/main.py` | Demo API with token-protected CRUD endpoints |
