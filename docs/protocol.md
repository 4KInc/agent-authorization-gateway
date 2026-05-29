# Receipt Chain Verification Protocol v0.4

> **Changelog:**
> - v0.4 — On-chain anchoring of Merkle roots to Base L2 mainnet. Batched (every 10 receipts or hourly). Async, never on trust path. Each anchor record includes the Base transaction hash, block number, and block timestamp. `GET /anchors` and `GET /anchors/verify/{tx_hash}` endpoints added.
> - v0.3.1 — `/verify-receipt` now performs bounded chain verification (single prev_receipt link check). Genesis returns PASS. Broken link returns FAIL with `PREV_LINK_BROKEN`. Missing predecessor returns INCONCLUSIVE with `PREV_NOT_FOUND`.
> - v0.3 — `action_digest` now mandatory in every proof (missing = `PROOF_DIGEST_MISSING`); `htm`/`htu` scoped as named limitation for v0.4.
> - v0.2 — documented authorization-side protocol (action digest, agent proof, registration, MCP tool signatures, transport authentication).

## Overview

The Receipt Chain Verification Protocol defines how authorization decisions are recorded as cryptographically signed, hash-chained, Merkle-anchored receipts that any third party can independently verify.

This document also specifies the client-facing protocol: how agents register, prove their identity, request authorization, and use the issued tokens. A third-party client can interoperate with the gateway using only this spec — no shared code required.

## Implementing a Client

The end-to-end flow for a client agent:

1. **Generate identity:** Create an Ed25519 keypair (one-time).
2. **Register:** Call the `register_agent` MCP tool with the public key (JWK). Receive an `agent_id` and `kid`.
3. **Build proof:** For each action, compute the `action_digest`, then sign a DPoP-style proof JWT binding the agent's identity to that specific action.
4. **Authorize:** Call the `authorize_action` MCP tool over an authenticated transport (bearer token), passing the proof. Receive a decision, a signed receipt, and (if approved) a 60-second scoped token.
5. **Execute:** Use the token as a `Bearer` token against the protected resource.
6. **Verify:** Optionally verify the receipt independently using the gateway's public key from `get_public_key`.

Each step is specified in full below.

---

## Action Digest Computation

The action digest is a SHA-256 hash of the canonicalized action intent. It binds a token and its receipt to one specific action. Both the gateway and the client must compute identical digests for the same input; a mismatch causes proof verification to fail.

**Source:** `gateway/tokens.py:32-47`, using `gateway/canonical.py`

### Algorithm

1. Build an intent object with these fields (exact names):

   ```json
   {
     "agent_id": "<agent_id>",
     "action": "<action>",
     "resource": "<resource>"
   }
   ```

2. If `parameters` is a non-empty dict, add it:

   ```json
   {
     "agent_id": "<agent_id>",
     "action": "<action>",
     "resource": "<resource>",
     "parameters": { ... }
   }
   ```

   `parameters` is **omitted** (not included as a key) when it is `None`, not provided, or an empty dict `{}`. In Python: `if parameters:` is the guard — empty dict is falsy and is treated the same as `None`.

3. Canonicalize the intent object using RFC 8785 (JCS):
   - Object keys are sorted by UTF-16 code unit values (per RFC 8785 §3.2.3).
   - No whitespace between tokens.
   - Strings are minimally escaped (only `"`, `\`, and control characters).
   - The result is UTF-8 bytes.

4. Compute SHA-256 of the canonical bytes.

5. Format the result as: `"sha256:" + lowercase_hex_digest`

### Worked Example (real output)

**Input:**
```
agent_id  = "worker-analytics-01"
action    = "read"
resource  = "staging-database"
parameters = {"query": "SELECT * FROM users LIMIT 10"}
```

**Canonical bytes (UTF-8 string):**
```
{"action":"read","agent_id":"worker-analytics-01","parameters":{"query":"SELECT * FROM users LIMIT 10"},"resource":"staging-database"}
```

Note: keys are sorted — `action` < `agent_id` < `parameters` < `resource` per UTF-16 code unit ordering.

**action_digest:**
```
sha256:002943d4252274c353a8533f2992027a3b1c0448c1d69ecb0c65481ee27beee5
```

**Without parameters:**

```
Canonical: {"action":"read","agent_id":"worker-analytics-01","resource":"staging-database"}
Digest:    sha256:d6eca099654632577774e95d6de45feddc17dc693dfd03077a6ffdd4f760fb47
```

---

## Agent Identity & Proof of Possession

Before authorizing any action, the gateway requires the agent to prove it holds the private key corresponding to a registered public key. This is a DPoP-style proof (inspired by RFC 9449) implemented as an EdDSA-signed JWT.

**Source:** `gateway/identity.py:100-128` (creation), `gateway/identity.py:131-205` (verification)

### Proof JWT Structure

**Header:**
```json
{
  "alg": "EdDSA",
  "typ": "JWT"
}
```

**Payload claims:**

| Claim | Type | Required | Verified | Description |
|-------|------|----------|----------|-------------|
| `sub` | string | Yes | Yes — must equal the `agent_id` in the request | The agent's registered identifier |
| `htm` | string | Yes | No — present by convention (RFC 9449) but not yet enforced (see Known Limitations) | HTTP method (always `"POST"`) |
| `htu` | string | Yes | No — present by convention but not yet enforced (see Known Limitations) | Target URL (default: `"agent-authorization-gateway"`) |
| `action` | string | Yes | Yes — must equal the `action` in the authorize request | The action being authorized |
| `resource` | string | Yes | Yes — must equal the `resource` in the authorize request | The target resource |
| `jti` | string | Yes | Yes — must be unique (replay cache, 30s TTL) | UUID v4, fresh per proof |
| `iat` | integer | Yes | Yes — must be within 30 seconds of server time | Unix timestamp (seconds) |
| `action_digest` | string | **Yes** | Yes — must equal the gateway's computed digest | The `action_digest` string (see above) |

**Signing:** The JWT is signed with the agent's Ed25519 private key using the `EdDSA` algorithm. The gateway verifies it against the public key registered for the `sub` agent_id.

### action_digest Binding

The `action_digest` claim is **mandatory**. The verification logic (`identity.py:191-201`) is:

```python
if expected_action_digest:
    proof_digest = claims.get("action_digest")
    if not proof_digest:
        raise ValueError("PROOF_DIGEST_MISSING")
    if proof_digest != expected_action_digest:
        raise ValueError("PROOF_DIGEST_MISMATCH")
```

- Missing `action_digest` → `PROOF_DIGEST_MISSING`
- Wrong `action_digest` → `PROOF_DIGEST_MISMATCH`
- Correct `action_digest` → passes

The reference `create_agent_proof()` auto-computes the digest from `(agent_id, action, resource)` when not explicitly provided. Third-party clients must compute it identically (see Action Digest Computation above).

### Known Limitations (v0.3)

**`htm` and `htu` are carried but not enforced.** Proofs include `htm` (HTTP method) and `htu` (target URL) by convention (RFC 9449), but the gateway does not currently verify them. Replay is bounded by the jti cache (30s TTL) and freshness window (30s). Endpoint binding via `htm`/`htu` enforcement is planned for v0.4.

### Freshness & Replay

- **Freshness window:** 30 seconds (`_PROOF_MAX_AGE = 30` at `identity.py:38`). The proof's `iat` must satisfy `time.time() - iat <= 30`. There is no explicit clock-skew allowance beyond this window.
- **Replay cache:** JTIs are cached for 30 seconds. A proof with a previously-seen JTI is rejected with `PROOF_REPLAY`. The cache is in-memory and distinct from the token JTI cache.

### Verification Order and Error Codes

The gateway verifies the proof in this order (`identity.py:146-203`). The first failure stops verification:

| Order | Check | Error Code |
|-------|-------|------------|
| 0 | Proof is present and non-empty | `NO_PROOF` (raised in `gateway_service.py:112`, before `verify_agent_proof` is called) |
| 1 | Proof is a valid JWT (parseable) | `INVALID_PROOF` |
| 2 | `sub` matches the request's `agent_id` | `AGENT_MISMATCH` |
| 3 | `sub` agent is in the registry | `UNREGISTERED_AGENT` |
| 4 | Ed25519 signature matches the registered public key | `INVALID_PROOF_SIGNATURE` |
| 5 | `iat` is within 30 seconds | `PROOF_EXPIRED` |
| 6 | `action` matches the request | `PROOF_ACTION_MISMATCH` |
| 7 | `resource` matches the request | `PROOF_RESOURCE_MISMATCH` |
| 8 | `action_digest` is present in proof | `PROOF_DIGEST_MISSING` |
| 9 | `action_digest` matches the gateway's computed digest | `PROOF_DIGEST_MISMATCH` |
| 10 | `jti` not in replay cache | `PROOF_REPLAY` |

### Example Proof (decoded, real output)

```json
{
  "sub": "worker-01",
  "htm": "POST",
  "htu": "agent-authorization-gateway",
  "action": "read",
  "resource": "staging-db",
  "jti": "38b42a0c-64fb-4484-a577-fe21634edb5d",
  "iat": 1779987015,
  "action_digest": "sha256:d7b394ebaa36ec5c1327b52d9dcb8514975eaad9ad154083116a37b26077792e"
}
```

The `action_digest` is always present and matches `compute_action_digest("worker-01", "read", "staging-db")`.
```

---

## Agent Registration

Before an agent can authorize actions, it must register its Ed25519 public key with the gateway.

**Source:** `gateway/identity.py:63-85` (AgentRegistry.register), `gateway/mcp_server.py:182-204` (MCP tool)

### Flow

1. Agent generates an Ed25519 keypair.
2. Agent exports the public key as a JWK with fields: `kty`, `crv`, `x` (base64url-encoded, no padding).
3. Agent calls the `register_agent` MCP tool with its chosen `agent_id` and the JWK as a JSON string.
4. Gateway parses the JWK, computes a key fingerprint (`kid = "agent-" + sha256(raw_public_key_bytes)[:16]`), and stores the mapping.
5. Gateway returns `{"status": "registered", "agent_id": "...", "kid": "agent-..."}`.

### JWK Format

The public key JWK must have exactly these fields:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "<base64url-encoded 32-byte public key, no padding>"
}
```

The `x` value is the raw Ed25519 public key bytes (32 bytes) encoded as base64url without `=` padding. The gateway decodes it by replacing `-`→`+`, `_`→`/`, adding padding, then base64-decoding (`identity.py:66-71`).

### Idempotency

Re-registering the same `agent_id` with a different key **overwrites** the previous registration (the `_agents` dict is keyed by `agent_id`). There is no error on re-registration.

### Registry Lifetime

The registry is in-memory. If the gateway restarts, all registrations are lost and agents must re-register. This is by design for the hackathon; a production deployment would back the registry with Firestore.

---

## MCP Tool Reference

The gateway exposes these tools via the Model Context Protocol (MCP) using FastMCP over Streamable HTTP.

**Source:** `gateway/mcp_server.py:61-204`

### `authorize_action`

Evaluate an agent's intended action against the security policy. Returns a decision, receipt, and (if approved) a 60-second scoped token.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `agent_id` | `str` | Yes | — | The agent's registered identifier |
| `action` | `str` | Yes | — | The intended action (e.g. `"read"`, `"query"`) |
| `resource` | `str` | Yes | — | The target resource (e.g. `"staging-database"`) |
| `agent_proof` | `str` | Yes | — | DPoP-style proof JWT (see Agent Identity section) |
| `parameters` | `str` | No | `"{}"` | JSON string of action-specific parameters |

**Note:** `parameters` is a **JSON string**, not a JSON object. The gateway parses it with `json.loads()`. If parsing fails, it wraps the raw string as `{"raw": parameters}`.

**Returns (JSON string):** On success:
```json
{
  "decision": "approve",
  "reason_codes": [],
  "token": "eyJ...",
  "receipt_hash": "sha256:...",
  "action_digest": "sha256:..."
}
```

On identity/proof error:
```json
{
  "error": "NO_PROOF",
  "detail": "NO_PROOF: agent_proof is required for every authorization request"
}
```

The `error` field contains the error code (see verification order table above). The `token` field is `null` for deny decisions.

### `register_agent`

Register an agent's Ed25519 public key.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent_id` | `str` | Yes | Unique identifier for the agent |
| `public_key_jwk` | `str` | Yes | **JSON string** of the Ed25519 public key JWK |

**Note:** `public_key_jwk` is a JSON **string** (double-encoded), not a JSON object. The gateway parses it with `json.loads()`.

**Returns (JSON string):**
```json
{
  "status": "registered",
  "agent_id": "worker-01",
  "kid": "agent-3aaa21d5e363b7c0"
}
```

### `get_public_key`

Get the gateway's Ed25519 signing public key as a JWK.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| *(none)* | — | — | — |

**Returns (JSON string):**
```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "kid": "<gateway-kid>",
  "use": "sig",
  "alg": "EdDSA",
  "x": "<base64url-encoded public key, no padding>"
}
```

> The actual values are deployment-specific. Fetch the live values from
> `GET /keys` on a running gateway.

### `get_chain_stats`

Get statistics about the current receipt chain.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| *(none)* | — | — | — |

**Returns (JSON string):**
```json
{
  "tenant": "hackathon-demo",
  "total_receipts": 42,
  "approvals": 35,
  "denials": 7,
  "merkle_root": "sha256:...",
  "policy_version": "sha256:..."
}
```

### `get_receipt_chain`

Get the full receipt chain for audit/verification.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| *(none)* | — | — | — |

**Returns (JSON string):** Array of receipt envelopes (body + sig + receipt_hash), ordered by sequence number.

### `verify_receipt`

Verify a single receipt's cryptographic integrity.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `receipt_json` | `str` | Yes | JSON string of a receipt envelope |

**Returns (JSON string):**
```json
{
  "receipt_integrity": "PASS",
  "chain_validity": "PASS",
  "errors": []
}
```

---

## Transport Authentication

The MCP server requires transport-level authentication on every request. This is enforced by middleware before any tool dispatch.

**Source:** `serve_mcp.py:109-142` (MCPTransportAuthMiddleware)

### Header Format

```
Authorization: Bearer <token>
```

The header name is `authorization` (case-insensitive per HTTP). The value must start with `Bearer ` (capital B, one space) followed by the token.

### Auth Modes

Configured via the `MCP_AUTH_MODE` environment variable (default: `"bearer"`):

| Mode | Env Vars Required | Behavior |
|------|-------------------|----------|
| `bearer` | `MCP_AUTH_TOKEN` | Static shared secret. Token in header must exactly equal `MCP_AUTH_TOKEN`. |
| `iam` | `MCP_IAM_AUDIENCE` | Google-signed ID token verified against Google's public keys with the specified audience. |
| `none` | `GATEWAY_DEV_MODE=true` | No transport auth. **Refused at startup** unless `GATEWAY_DEV_MODE=true`. |

### Error Responses

| Condition | HTTP Status | Body |
|-----------|-------------|------|
| Missing `Authorization` header | 401 | `{"error": "UNAUTHORIZED", "detail": "Missing Authorization: Bearer <token> header"}` |
| Wrong bearer token | 401 | `{"error": "INVALID_TOKEN", "detail": "Invalid bearer token"}` |
| Invalid IAM token | 401 | `{"error": "INVALID_TOKEN", "detail": "Invalid Google ID token"}` |

All 401 responses include the `WWW-Authenticate: Bearer` response header.

### Exempt Endpoints

All MCP tool calls require transport auth. There are no anonymous MCP endpoints. The REST API's `GET /keys` endpoint (separate from MCP) is anonymous — it serves the gateway's public key for independent verification.

### Startup Safety

The server refuses to start (`sys.exit(1)`) if:
- `MCP_AUTH_MODE=none` and `GATEWAY_DEV_MODE` is not `true`
- `MCP_AUTH_MODE=bearer` and `MCP_AUTH_TOKEN` is empty
- `MCP_AUTH_MODE` is not one of `bearer`, `iam`, `none`

### Connecting with the MCP SDK

```python
from mcp.client.streamable_http import streamablehttp_client

async with streamablehttp_client(
    url="http://gateway-host:8090/mcp",
    headers={"Authorization": "Bearer <MCP_AUTH_TOKEN>"},
) as (read_stream, write_stream, _):
    async with ClientSession(read_stream, write_stream) as session:
        await session.initialize()
        result = await session.call_tool("authorize_action", {...})
```

---

## Receipt Format

Each receipt is a 3-part envelope:

```json
{
  "body": { ... },      // Canonical JSON, 9-10 fields
  "sig": { ... },       // Ed25519 signature
  "receipt_hash": "..." // SHA-256 of canonical body
}
```

### Body Fields

| Field | Type | Description |
|-------|------|-------------|
| `v` | string | Protocol version ("1") |
| `tenant` | string | Tenant identifier |
| `seq` | string | Monotonically increasing sequence number |
| `ts` | string | ISO 8601 timestamp (UTC) |
| `request_digest` | string | SHA-256 of canonicalized action intent (= action_digest) |
| `policy_version` | string | SHA-256 hash of the policy in effect |
| `decision` | string | "approve" or "deny" |
| `reasons` | string[] | Reason codes (empty for approve) |
| `prev_receipt` | string | SHA-256 hash of the previous receipt (genesis = null hash) |
| `token_jti` | string? | JTI of the issued token (present only for approve) |

### Signature

```json
{
  "alg": "EdDSA",
  "kid": "gateway-tenant-hexid",
  "value": "base64url-encoded Ed25519 signature"
}
```

The signature is computed over the **canonical JSON** of the body (RFC 8785 JCS subset).

### Receipt Hash

```
receipt_hash = "sha256:" + hex(SHA-256(canonicalize(body)))
```

## Chain Properties

1. **Monotonic sequences:** `seq` values are dense integers starting at 1
2. **Hash linkage:** Each receipt's `prev_receipt` equals the previous receipt's `receipt_hash`
3. **Genesis:** The first receipt's `prev_receipt` is `sha256:` followed by 64 zeros
4. **Immutability:** Modifying any field in any receipt invalidates the hash chain

## Bounded Chain Verification

The `/verify-receipt` endpoint (and `verify_receipt` MCP tool) perform two independent checks:

1. **Receipt integrity**: signature verification + body hash match. Reports `receipt_integrity: PASS` or `FAIL`.
2. **Bounded chain check**: load the immediate predecessor (the receipt at `seq - 1`), compute its hash, and compare to the current receipt's `prev_receipt` field. Reports `chain_validity: PASS`, `FAIL`, or `INCONCLUSIVE`.

The bounded check requires one extra storage read but enables tamper detection on any individual receipt without walking the entire chain. For full-chain verification (every link from genesis to head), use `/verify-chain`.

### chain_validity values

| Value | Meaning |
|-------|---------|
| `PASS` | Predecessor was loaded and its hash matches the receipt's `prev_receipt` field. Or, this is the genesis receipt (no predecessor exists, so no broken link is possible). |
| `FAIL` | Predecessor was loaded and its hash does NOT match the receipt's `prev_receipt` field. Indicates tampering. |
| `INCONCLUSIVE` | Predecessor could not be loaded (`PREV_NOT_FOUND`) or another error prevented the check (`PREV_LOAD_FAILED`, `SEQ_INVALID`). |

### Error codes (added in v0.3.1)

| Code | When |
|------|------|
| `PREV_NOT_FOUND` | Predecessor receipt at `seq - 1` was not found in the chain store |
| `PREV_LINK_BROKEN` | Predecessor exists but its hash does not match the current receipt's claimed `prev_receipt` |
| `PREV_LOAD_FAILED` | Storage error while loading the predecessor |
| `SEQ_INVALID` | The receipt's `seq` field could not be parsed as an integer |

## Verification Algorithm

```python
for each receipt in chain:
    1. Canonicalize the body (RFC 8785)
    2. Compute SHA-256 of canonical bytes
    3. Compare computed hash to claimed receipt_hash
    4. Verify Ed25519 signature over canonical bytes using public key
    5. Check kid matches the signing key
    6. Verify seq is expected (previous seq + 1)
    7. Verify prev_receipt matches previous receipt's hash
```

If any step fails, the verification reports the specific receipt index and failure type.

## Merkle Anchoring

Receipts are batched into a Merkle tree using SHA-256 with RFC 6962 domain separation:

- **Leaf:** `SHA-256("BI_RECEIPT_LEAF_V1" || 0x00 || receipt_hash_bytes)`
- **Node:** `SHA-256("BI_RECEIPT_NODE_V1" || 0x00 || left || right)`
- **Odd leaf:** Promoted unchanged (no duplication)

The Merkle root is written to an anchor sink (local signed log or GCS with object versioning) to provide external tamper evidence.

## Token Binding

Approved receipts include `token_jti` — the JTI of the issued authorization token. This creates an inseparable binding:
- The receipt proves the token was authorized
- The token references the receipt via `receipt_hash`
- Neither can exist without the other

## Cryptographic Choices

| Primitive | Standard | Rationale |
|-----------|----------|-----------|
| Signing | Ed25519 (EdDSA, RFC 8032) | Fast, compact, no parameter debates |
| Hashing | SHA-256 | Universal, hardware-accelerated |
| Canonicalization | RFC 8785 (JCS) | Deterministic JSON for reproducible hashes |
| Merkle | RFC 6962 domain separation | Prevents second-preimage attacks |
| Tokens | JWT with EdDSA (RFC 8037) | Asymmetric verification, industry standard |

## Reference Implementation

The reference implementation is in this repository:
- `gateway/tokens.py` — Ed25519 token issuance and action digest computation
- `gateway/identity.py` — Agent registration, DPoP proof creation and verification
- `gateway/receipts.py` — Receipt creation and chain management
- `gateway/verify.py` — Independent verification
- `gateway/canonical.py` — JCS canonicalization
- `gateway/merkle.py` — Merkle tree construction
- `gateway/mcp_server.py` — MCP tool definitions
- `gateway/base_anchor.py` — On-chain anchoring to Base L2
- `gateway/anchor_scheduler.py` — Batched async anchor scheduler
- `serve_mcp.py` — Transport authentication middleware

---

## On-Chain Merkle Anchoring (v0.4)

Tamper evidence for the audit chain comes from three independent layers:

1. **Cryptographic linkage** (every receipt): SHA-256 chain of prev_receipt hashes. Detects modification of any individual receipt.
2. **Signed receipts** (every receipt): Ed25519 signatures over canonical receipt bodies. Detects forgery without the gateway's private key.
3. **On-chain anchoring** (batched, hourly): Merkle root of the chain head committed to Base L2 mainnet via a value-0 transaction whose calldata is the root. Detects retroactive rewriting of historical chain state, even by an attacker with full gateway and Firestore access, because the root at each anchored block height is publicly recorded.

### Anchoring Policy

Anchoring is performed by a background scheduler running on the REST gateway service (single source, no nonce races). Triggers:
- Every 10 new receipts since the last anchor, OR
- Every 1 hour, whichever comes first

Each anchor commits the current chain-head Merkle root to Base via a transaction to the burn address (`0x0000...0000`) with the root as calldata. Gas cost is approximately 21,000 + 16*32 gas, well under 1 cent at Base L2 prices.

### Anchor Record Format

Stored in Firestore at `tenants/{tenant}/anchors/{tx_hash_prefix}` and exposed via `GET /anchors`:

```json
{
  "merkle_root": "sha256:<64 hex chars>",
  "tx_hash": "0x<64 hex chars>",
  "block_number": 12345678,
  "block_timestamp": 1735689600,
  "chain_head_seq": 142,
  "anchored_at": "2026-05-29T15:42:00Z",
  "chain_id": 8453,
  "basescan_url": "https://basescan.org/tx/0x..."
}
```

### Independent Anchor Verification

Anyone can verify an anchor without trusting the gateway:

```python
from web3 import Web3
w3 = Web3(Web3.HTTPProvider("https://mainnet.base.org"))
tx = w3.eth.get_transaction("0x<tx_hash>")
assert tx.input.hex()[2:] == "<merkle_root_hex>"
block = w3.eth.get_block(tx.blockNumber)
print(f"Anchored at block {tx.blockNumber}, timestamp {block.timestamp}")
```

Or use the gateway's verification endpoint:

```
GET /anchors/verify/{tx_hash}
```

Returns:
```json
{
  "tx_found": true,
  "calldata_matches_recorded_root": true,
  "block_number": 12345678,
  "block_timestamp": 1735689600,
  "merkle_root_on_chain": "sha256:...",
  "merkle_root_recorded": "sha256:..."
}
```

### Failure Modes

If Base mainnet is unreachable when an anchor cycle runs:
- The anchor is skipped
- The receipt chain continues unaffected
- The next anchor cycle retries with the new chain head

If the gateway is compromised and stops anchoring, everything before the last legitimate anchor is cryptographically committed on-chain. The time between the last anchor and the moment of compromise is unprotected.
