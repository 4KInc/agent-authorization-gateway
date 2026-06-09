# Receipt Chain Verification Protocol v0.5

**Standards intent:** BlockIntel intends to submit the Gate protocol to the IETF or another appropriate standards body in 2027 once v1.0 ships and at least one external reference implementation exists. The protocol is designed to be implementation-neutral and is being developed in the open with that future submission in mind.

> **Changelog:**
> - v0.5 — Two-step proof-of-possession registration flow (`POST /agents/register-challenge` + `POST /agents/register`). Challenge nonce: 60s TTL, single-use. Agent ID validation: `[a-zA-Z0-9_-]{1,256}`. JWK validation: `kty=OKP`, `crv=Ed25519`, `x` must decode to 32 bytes. Registration now has replace semantics (no HTTP 409 on re-registration). `verify_chain` supports partial chains via `start_seq`. MCP tools namespaced (`gateway_*`, `auditor_*`); old names kept as aliases.
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
2. **Register (two steps):** Call `gateway_register_challenge` with your `agent_id` to get a nonce, then call `gateway_register_agent` with the public key JWK and a signed registration proof. Receive an `agent_id` and `kid`. The nonce expires in 60 seconds and is single-use.
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

Before an agent can authorize actions, it must register its Ed25519 public key with the gateway. Registration uses a two-step proof-of-possession (PoP) flow to ensure the submitting party controls the private key being registered.

**Source:** `gateway/identity.py:63-85` (AgentRegistry.register), `gateway/mcp_server.py:182-204` (MCP tool)

### Two-Step PoP Flow

**Step 1 — Obtain a challenge nonce**

```
POST /agents/register-challenge
{"agent_id": "<agent_id>"}

200 OK
{"nonce": "<hex_nonce>", "expires_in": 60}
```

The nonce has a **60-second TTL** and is **single-use** — it is consumed the moment it is successfully verified. Submitting an expired or already-used nonce returns HTTP 400.

**Step 2 — Register with proof**

```
POST /agents/register
{
  "agent_id": "<agent_id>",
  "public_key": { "kty": "OKP", "crv": "Ed25519", "x": "<base64url>" },
  "registration_proof": "<EdDSA JWT>"
}
```

The `registration_proof` JWT payload:
```json
{
  "sub": "<agent_id>",
  "nonce": "<nonce from step 1>",
  "iat": <unix_timestamp>
}
```

The JWT must be signed with the agent's Ed25519 private key. The gateway verifies the signature against the `public_key` field in the same request. Both steps must complete within the nonce TTL.

### Agent ID Validation

`agent_id` must satisfy: `[a-zA-Z0-9_-]{1,256}`

- 1 to 256 characters
- Alphanumeric characters, hyphens (`-`), and underscores (`_`) only
- Case-sensitive

Requests with an `agent_id` outside this pattern are rejected with HTTP 422.

### JWK Validation

The public key JWK must satisfy all of the following:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "<base64url-encoded 32-byte public key, no padding>"
}
```

| Field | Required value | Rejection if violated |
|-------|---------------|----------------------|
| `kty` | `"OKP"` | HTTP 422 |
| `crv` | `"Ed25519"` | HTTP 422 |
| `x` | base64url string decoding to exactly 32 bytes | HTTP 422 |

The `x` value is decoded by replacing `-`→`+`, `_`→`/`, restoring `=` padding, then standard base64-decoding (`identity.py:66-71`).

### Replace Semantics

Re-registering the same `agent_id` (with a new PoP proof) **replaces** the previous key. There is no HTTP 409 on re-registration. The old key is immediately invalidated and the new `kid` takes effect for all subsequent authorization requests.

### Registry Lifetime

The registry is backed by Firestore at `tenants/{tenant}/agent_registry/{agent_id}` and an in-memory cache. Restarts reload from Firestore.

---

## MCP Tool Reference

The gateway exposes these tools via the Model Context Protocol (MCP) using FastMCP over Streamable HTTP.

**Source:** `gateway/mcp_server.py:61-204`

### Tool Namespacing

MCP tools are namespaced by service prefix:

| Prefix | Service | Example tool |
|--------|---------|-------------|
| `gateway_` | Core authorization gateway | `gateway_authorize_action` |
| `auditor_` | Policy Auditor agent | `auditor_query_compliance` |

The old unnamespaced names (`authorize_action`, `register_agent`, etc.) are retained as **backward-compatible aliases** and will not be removed before v1.0. New integrations should use the prefixed names.

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

### Partial Chain Verification

`verify_chain` (both `GET /verify-chain` and the `verify_chain` MCP tool) supports **partial chains**. The caller may supply a `start_seq` parameter; verification begins at that sequence number rather than requiring `seq=1` as the starting point. The first receipt in a partial chain is treated as the local genesis — its `prev_receipt` is trusted as a given rather than verified. This allows auditors to verify a recent window of receipts without loading the entire history.

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

---

## AAR/AARP Conformance

Gate receipts are structurally conformant with the Agent Action Receipt Profile (AARP v0.1) maintained by PipeLab. Both systems use Ed25519 signing, SHA-256 hashing, RFC 8785 JCS canonicalization, and `prev_hash` chaining. The following table maps Gate receipt fields to their AAR equivalents:

### Field Mapping: Gate to AAR

| Gate Field | AAR Field | Type | Notes |
|------------|-----------|------|-------|
| `seq` | `sequence_number` | string (numeric) | Monotonically increasing, dense from 1 |
| `decision` | `action_result` | string | Gate uses `"approve"` / `"deny"`; AAR uses `"allowed"` / `"denied"` |
| `request_digest` | `action_hash` | string | SHA-256 of canonicalized action intent |
| `policy_version` | `policy_hash` | string | SHA-256 of the policy document in effect |
| `prev_receipt` | `prev_hash` | string | SHA-256 of the previous receipt's canonical body |
| `receipt_hash` | `hash` | string | SHA-256 of the current receipt's canonical body |
| `sig.value` | `signature` | string (base64url) | Ed25519 signature over canonical body bytes |
| `sig.kid` | `signer_id` | string | Key identifier for the signing key |
| `sig.alg` | `signature_algorithm` | string | Always `"EdDSA"` in both systems |
| `ts` | `timestamp` | string (ISO 8601) | UTC timestamp of the decision |
| `v` | `version` | string | Protocol version identifier |
| `tenant` | `issuer` | string | Scoping identifier for the receipt chain |
| `reasons` | `reason_codes` | string[] | Reason codes for deny decisions |

### Gate Extensions Beyond AAR

Gate extends the AAR base schema with the following fields that have no AAR equivalent:

| Gate Field | Purpose |
|------------|---------|
| `token_jti` | JTI of the issued authorization token (approve only). Creates an inseparable binding between the receipt and the token it authorized. |
| `resource_registration_id` | Reference to a registered resource entry (optional). Enables resource-scoped policy enforcement. |

### Conformance Statement

Gate receipts are structurally conformant with the Agent Action Receipt Profile (AARP v0.1). Both use Ed25519, SHA-256, RFC 8785 JCS canonicalization, and `prev_hash` chaining. The cryptographic verification algorithm is identical: canonicalize the body, hash it, verify the Ed25519 signature, and check the `prev_hash` link. A verifier written for AAR receipts can verify Gate receipts with a field-name mapping layer and vice versa.

Gate extends AAR with token_jti binding (linking receipts to authorization tokens), resource_registration_id (resource-scoped enforcement), and Merkle anchoring to Base L2 mainnet (external tamper evidence). These extensions are additive — they do not break AAR verification, which ignores unknown fields in the canonical body.

An AAR compatibility mode (emitting receipts with AAR field names alongside Gate names) and an AAR verification endpoint (accepting AAR-format receipts) are planned for v1.0.

---

## Latency Characteristics

Gate's authorization hot path is designed for minimal, predictable latency.

### Hot Path Composition

The authorization decision path consists of three deterministic operations:

1. **Policy evaluation**: YAML rule matching against the request's agent, action, and resource fields.
2. **Ed25519 signing**: Sign the canonical receipt body (64-byte signature, ~50 microseconds on modern hardware).
3. **SHA-256 hashing**: Compute the receipt hash and action digest.

No LLM inference, no external API calls, and no semantic analysis are on the hot path.

### Measurement

Every authorization response includes the `X-Gate-Decision-Ms` header, reporting the wall-clock time (in milliseconds) from request parsing to decision completion. The `X-Gate-Hot-Path` header reports the persistence mode (`sync` or `async`).

**Typical latency**: 2-5ms for policy evaluation + signing + hashing, excluding Firestore persistence.

### Persistence Modes

| Mode | Env Var | Behavior | Latency Impact |
|------|---------|----------|----------------|
| `sync` (default) | `HOT_PATH_MODE=sync` | Firestore write completes before the response is returned. The caller is guaranteed that the receipt is persisted when it receives the token. | +20-50ms depending on network round-trip to Firestore. |
| `async` | `HOT_PATH_MODE=async` | Receipt is buffered in-memory and flushed to Firestore asynchronously. The decision and token are returned immediately. | Near-zero persistence overhead. Trade-off: a process crash before flush could lose buffered receipts (the token would still be valid but the receipt would be missing). |

In both modes, the cryptographic operations (signing, hashing, chain linkage) are performed synchronously before the response. The `async` mode only defers the Firestore write, not the security-critical operations.

### What Is NOT Measured

The `X-Gate-Decision-Ms` header does not include:
- Network latency between the client and the gateway
- TLS handshake time
- Firestore write latency in `sync` mode (measured separately in structured logs)
- MCP protocol framing overhead

---

## Parameters Confidentiality

The `parameters` field is included in the signed receipt body and is therefore part of the permanent, hash-chained audit trail. Receipt contents may be exported in Audit Packets, shared with auditors, or stored in Firestore.

**Sensitive data (credentials, PII, API keys, etc.) should NOT be placed in the `parameters` field.**

Instead, use references:
- Database query: pass a `query_id` or `query_hash`, not the raw SQL
- User data: pass a `user_id`, not the user's name or email
- API calls: pass an `endpoint_id` and `request_hash`, not the full request body

If parameters must contain data that should not appear in the audit trail, consider:
1. Hashing the sensitive portions and including only the hash
2. Using opaque reference identifiers that can be resolved by authorized parties

A `parameters_hash` option (storing a hash of parameters in the receipt while keeping the plaintext in a separate access-controlled store) is on the v2.0 roadmap.

---

## Identity Federation

### DPoP and SPIFFE Compatibility

Gate's agent identity model uses Ed25519 proof of possession (DPoP-style, inspired by RFC 9449). Each agent generates an Ed25519 keypair, registers the public key via the challenge-response flow, and signs a fresh proof JWT for every authorization request.

This model is compatible with SPIFFE (Secure Production Identity Framework for Everyone):

- An agent's SPIFFE SVID (SPIFFE Verifiable Identity Document) can derive the Ed25519 keypair used for Gate registration. The X.509-SVID's key material or a key derived from the SVID's identity can serve as the agent's Gate identity.
- Gate does not require a SPIRE server or any SPIFFE infrastructure. DPoP is simpler and self-contained — an agent only needs an Ed25519 keypair and access to the Gate registration endpoint.
- For organizations already using SPIFFE, Gate can accept SVID-derived keys in the registration flow. The agent registers its SPIFFE-derived Ed25519 public key via the standard two-step PoP flow. No changes to the Gate registration protocol are required.

### Positioning

| Identity Model | Complexity | Infrastructure Required | Gate Support |
|---------------|------------|------------------------|--------------|
| Gate DPoP (native) | Low | None beyond Gate | Current (v0.5) |
| SPIFFE SVID-derived | Medium | SPIRE server or SPIFFE-compatible runtime | Compatible now (register SVID-derived key) |
| WIMSE token exchange | High | WIMSE token service | v2.0 roadmap |

WIMSE (Workload Identity in Multi-System Environments) token exchange — accepting a WIMSE token, extracting the agent identity, and issuing a Gate DPoP credential — is on the v2.0 roadmap.

---

## Delegation Chains

When an agent delegates a sub-task to another agent, the child agent can include an optional `delegation_context` in its authorization request. This creates a verifiable link between the parent's authorization and the child's, forming a delegation tree that auditors can trace back to the original human principal.

### The `delegation_context` Field

The `delegation_context` is an optional object on the `POST /authorize` request body:

```json
{
  "agent_id": "agent-B",
  "action": "query",
  "resource": "analytics-db",
  "agent_proof": "eyJ...",
  "delegation_context": {
    "parent_agent_id": "agent-A",
    "parent_receipt_hash": "sha256:abc123...",
    "human_principal": "alice@example.com",
    "depth": 1
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `parent_agent_id` | string | Yes | Agent ID of the delegating (parent) agent |
| `parent_receipt_hash` | string | No | Receipt hash from the parent's own authorization. Links this child authorization to the parent's receipt in the chain. |
| `human_principal` | string | No | The human identity that the delegation chain traces back to (e.g., the user who initiated the top-level task) |
| `depth` | integer | Yes | Delegation depth: 1 = direct delegation from the parent, 2 = the parent was itself delegated to, etc. Maximum depth is 10. |

When present, the `delegation_context` is included in the signed receipt body (alongside `token_jti` and `resource_registration_id`). When absent, the field is omitted from the receipt for backward compatibility — existing receipts without delegation context remain valid.

### Receipt Body with Delegation

An approved receipt for a delegated action includes the delegation context:

```json
{
  "body": {
    "v": "1",
    "tenant": "hackathon-demo",
    "seq": "42",
    "ts": "2026-06-08T12:00:00.000Z",
    "request_digest": "sha256:...",
    "policy_version": "sha256:...",
    "decision": "approve",
    "reasons": [],
    "prev_receipt": "sha256:...",
    "token_jti": "550e8400-e29b-41d4-a716-446655440000",
    "delegation_context": {
      "parent_agent_id": "agent-A",
      "parent_receipt_hash": "sha256:abc123...",
      "human_principal": "alice@example.com",
      "depth": 1
    }
  },
  "sig": { "alg": "EdDSA", "kid": "...", "value": "..." },
  "receipt_hash": "sha256:..."
}
```

### Depth Limits

The maximum delegation depth is **10**. This prevents unbounded delegation chains that could be difficult to audit or that could indicate a misconfigured agent topology. The gateway rejects any `delegation_context` with `depth` greater than 10 at the request validation layer (HTTP 422).

### How Parent Receipt Hash Links Work

The `parent_receipt_hash` creates a cryptographic link between two receipts in the chain:

1. **Agent A** authorizes `read` on `staging-db` and receives receipt with hash `sha256:aaa...`.
2. **Agent A** delegates a sub-query to **Agent B**.
3. **Agent B** authorizes `query` on `analytics-db`, including `delegation_context.parent_receipt_hash = "sha256:aaa..."`.
4. Agent B's receipt now contains a signed, tamper-evident reference back to Agent A's receipt.

An auditor can follow the `parent_receipt_hash` links to reconstruct the full delegation tree and verify that every link in the chain was authorized by the gateway.

### Worked Example: Agent A Delegates to Agent B

**Step 1:** Agent A requests authorization for its own task.

```
POST /authorize
{
  "agent_id": "agent-A",
  "action": "orchestrate",
  "resource": "pipeline/etl-daily",
  "agent_proof": "<agent-A-proof>"
}

Response:
{
  "decision": "approve",
  "receipt_hash": "sha256:f8c3a1b2d4e5..."
}
```

**Step 2:** Agent A decides it needs Agent B to perform a sub-task. Agent B requests its own authorization, referencing Agent A's receipt.

```
POST /authorize
{
  "agent_id": "agent-B",
  "action": "query",
  "resource": "analytics-db",
  "agent_proof": "<agent-B-proof>",
  "delegation_context": {
    "parent_agent_id": "agent-A",
    "parent_receipt_hash": "sha256:f8c3a1b2d4e5...",
    "human_principal": "ops-team@example.com",
    "depth": 1
  }
}

Response:
{
  "decision": "approve",
  "receipt_hash": "sha256:7b9e0d3c6a2f..."
}
```

Agent B's receipt (seq=42) now contains the `delegation_context` in its signed body, permanently recording that this action was performed on behalf of Agent A, which was itself acting on behalf of `ops-team@example.com`. Both receipts are independently verifiable, and the delegation link is tamper-evident because it is covered by the Ed25519 signature.
