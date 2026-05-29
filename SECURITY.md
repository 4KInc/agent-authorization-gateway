# Security Model

## What the Gateway Defends Against

### 1. Unauthorized agent actions
Every privileged action requires a short-lived, scoped authorization token. Without a valid token from the Gateway, the protected resource rejects the request. The token is bound to a specific action, resource, and agent via an `action_digest` claim — it cannot be repurposed for a different action.

### 2. Undetected policy violations
Every authorization decision (approve AND deny) produces a signed receipt with Ed25519. The receipt is linked into a hash chain (each receipt's `prev_receipt` field references the previous receipt's SHA-256 hash). Tampering with any receipt in the chain breaks the linkage and is cryptographically detectable by any party with the public key.

### 3. Audit trail manipulation
Receipts are anchored in a Merkle tree (SHA-256, RFC 6962 domain separation). The Merkle root summarizes the entire chain state at any point. An anchor sink writes roots to an append-only store (Cloud Storage with object versioning or a local signed log), making retroactive rewriting evident even if the Gateway's Firestore is compromised.

### 4. Standing credential abuse
Agents never hold persistent credentials to protected resources. Every action requires a fresh 60-second token scoped to exactly one action. If an agent is compromised, the blast radius is limited to actions it can get authorized — and every attempt is recorded in the receipt chain regardless of outcome.

### 5. Token replay
Tokens include a unique `jti` claim. The resource-side middleware maintains a replay cache (TTL = token TTL + clock skew). A token used once cannot be used again, even within its validity window.

### 6. Token forgery
Tokens are signed with Ed25519 (EdDSA, RFC 8037). The signing key is held only by the Gateway. Protected resources verify tokens using the Gateway's public key fetched from `/keys`. A rogue agent cannot forge a valid token without the Gateway's private key.

### 7. Cross-action token misuse
The `action_digest` claim in every token is a SHA-256 hash of the canonicalized action intent (agent_id + action + resource + parameters). The resource-side middleware recomputes this digest from the incoming request and compares it to the token's claim. A token authorized for "read on staging-db" cannot be used for "delete on production-db."

## What the Gateway Does NOT Defend Against

### 1. Compromised Gateway host
If an attacker gains code execution on the Gateway's runtime (e.g., Cloud Run container escape), they can access the signing private key and issue arbitrary tokens and receipts. **Mitigation:** Use Cloud Run's sandboxing, restrict IAM to least privilege, rotate signing keys periodically, and anchor Merkle roots to an external sink that the Gateway cannot retroactively rewrite.

### 2. Signing key exfiltration
If the Ed25519 private key is extracted from the Gateway process, an attacker can forge valid tokens and receipts offline. **Mitigation:** The current implementation loads a shared signing key from GCP Secret Manager at startup. Secret Manager protects the key at rest and gates access via IAM (only services with `roles/secretmanager.secretAccessor` on the specific secret can read it), but exposes the key material to the runtime process. For higher-assurance deployments, the key should be moved to Cloud KMS or an HSM, where the key never leaves the secure boundary and signing is performed via API calls. The signing path is encapsulated in `gateway/signing_key.py` — swapping the loader to KMS-backed signing is a self-contained change.

### 3. Side-channel attacks on the resource
The Gateway protects the authorization boundary, not the resource itself. SQL injection, SSRF, or logic bugs in the protected resource are outside the Gateway's scope. **Mitigation:** Standard application security practices on the resource side.

### 4. Social engineering of the policy author
If a human is tricked into deploying a permissive policy (e.g., allowing all actions on production), the Gateway will faithfully authorize those actions and produce valid receipts. The receipts prove the policy was followed — but the policy was wrong. **Mitigation:** Policy change auditing, human-in-the-loop for policy updates, separation of duties between policy authors and Gateway operators.

### 5. Denial of service
The Gateway does not implement robust DDoS protection. Rate limiting is per-agent and in-memory (persisted to Firestore across restarts, but not distributed across instances). **Mitigation:** Use Cloud Run's built-in autoscaling and Cloud Armor for DDoS protection in production.

### 6. LLM prompt injection (ADK agent surface)
The ADK chat agent uses Gemini to interpret user requests. A prompt injection could cause the agent to misinterpret a request or provide misleading information. **Mitigation:** The chat agent has read-only access to the receipt chain and verification tools. Privileged operations (authorize_action, register_agent, update_policy) are exposed only via MCP, never via the LLM surface. This is documented as "LLM blast radius containment" — even a fully compromised chat session cannot issue tokens or modify policy.

## Tamper-Evidence Trust Assumptions

The tamper-evidence guarantee relies on:

1. **Single shared signing key:** All gateway surfaces (REST, MCP, ADK) load the SAME Ed25519 signing key from GCP Secret Manager at startup. There is exactly one kid in use across all services and all receipts. No per-instance key generation.
2. **Receipt signing key integrity:** The Ed25519 private key has not been exfiltrated.
2. **Anchor sink write-once property:** The Merkle root anchor destination (Cloud Storage with versioning, or the local signed log) is not retroactively rewritable without leaving evidence.
3. **Verifier independence:** The receipt verification code (`gateway/verify.py`) uses only the public key and standard cryptographic operations. It does not trust the Gateway — it verifies against math.

4. **Cross-surface persistence:** All gateway surfaces (REST, MCP, ADK) persist receipts to a shared Firestore collection (`tenants/{tenant}/receipts/`), with monotonic seq assignment resumed from Firestore on cold start. The chain is unbroken across surfaces and container restarts.

**Important:** Firestore receipts are mutable by any operator with write access to the database. Tamper-evidence does not derive from Firestore — it derives from the Ed25519 signatures on each receipt and the external anchor sink. If a receipt is modified in Firestore, `verify_receipt` will detect the tampering because the signature will not match the modified body. Firestore is a convenience store for querying and display; the cryptographic chain is the source of truth.

If any of the above assumptions are violated, the tamper-evidence guarantee degrades to "detection after the fact" rather than "prevention."

### Operational Invariants

- **Receipt persistence is a hard error.** Tokens are not returned to callers when the receipt could not be persisted. This prevents authorization without audit. If Firestore is unreachable, the caller receives `RECEIPT_PERSIST_FAILED` and no token — never a token with a missing receipt.
- **No silent exception swallowing on security-critical paths.** Receipt persistence failures are logged with full tracebacks and surfaced to callers. The `try/except pass` pattern is prohibited on the authorize path.

## Cryptographic Choices

**Demo chain reset (2026-05-28):** The receipt chain was reset as part of the migration to a single shared signing key in Secret Manager. Receipts prior to this date are preserved in `legacy_receipts_20260528` for audit history but are unverifiable under the current key. All receipts issued after this date are verifiable against the shared key in `/keys`.

| Primitive | Choice | Why |
|-----------|--------|-----|
| Receipt signing | Ed25519 (EdDSA) | Fast, compact (64-byte signatures), no key size debates, mandatory in the Receipt Chain Verification Protocol v0.1 |
| Token signing | Ed25519 (EdDSA) | Asymmetric — resources verify with public key only, no shared secret needed |
| Hash chain | SHA-256 with `prev_receipt` linkage | Standard, well-understood, compatible with Merkle tree construction |
| Merkle tree | SHA-256, RFC 6962 domain separation | Prevents second-preimage attacks on the tree structure |
| Canonicalization | RFC 8785 (JCS subset) | Deterministic JSON serialization for reproducible hashes across languages |
| Token format | JWT with EdDSA signature | Industry-standard token format, verifiable by any JWT library supporting EdDSA |

## MCP / API Authentication

Token issuance requires **two independent layers of authentication**:

### Layer 1: Transport Authentication
The MCP server requires a valid credential on every connection:

| Mode | Env var | Description |
|------|---------|-------------|
| `bearer` (default) | `MCP_AUTH_TOKEN` | Static shared secret in `Authorization: Bearer <token>` header |
| `iam` | `MCP_IAM_AUDIENCE` | Google-signed ID token, verified against Google's public keys |
| `none` | `GATEWAY_DEV_MODE=true` | **Dev only.** Server refuses to start in `none` mode without `GATEWAY_DEV_MODE=true`. |

A startup assertion prevents an open MCP server from being deployed accidentally: if `MCP_AUTH_MODE=none` and `GATEWAY_DEV_MODE` is not `true`, the server exits non-zero with a fatal error.

### Layer 2: Application Identity (DPoP)
Every `authorize_action` call requires a DPoP-style proof JWT signed by the agent's registered Ed25519 private key. The proof binds the agent's identity to the specific action being authorized.

**Enforcement is mandatory and lives in `GatewayService.authorize()`** — the single chokepoint that all three surfaces (MCP, REST, ADK) call. There is no optional bypass.

Calls without a valid proof are rejected with specific error codes **before** policy evaluation or token issuance:
- `NO_PROOF` — no `agent_proof` provided
- `UNREGISTERED_AGENT` — agent not in the registry
- `INVALID_PROOF_SIGNATURE` — proof signed with a key that doesn't match the registered key
- `PROOF_EXPIRED` — proof older than 30 seconds
- `PROOF_REPLAY` — proof JTI already used (distinct replay cache from token JTIs)
- `PROOF_ACTION_MISMATCH` — proof action doesn't match the request action
- `PROOF_RESOURCE_MISMATCH` — proof resource doesn't match the request resource
- `PROOF_DIGEST_MISMATCH` — proof `action_digest` doesn't match the computed digest

### Anonymous Endpoints
`GET /keys` (REST API) is the only anonymous endpoint — public key distribution is a feature, not a leak. All other endpoints and MCP tools require transport authentication.

### Threat: Anonymous Token Issuance
**Status: Mitigated.** Previously, the MCP server accepted unauthenticated calls and `authorize_action` did not enforce DPoP proofs. This allowed anyone with the Cloud Run URL to mint real Ed25519 tokens. This is now closed at both layers: transport auth rejects anonymous connections, and the service layer rejects calls without a valid DPoP proof.

### Known Limitation: htm/htu Not Enforced (v0.3)
DPoP-style proofs carry `htm` (HTTP method) and `htu` (target URL) claims by convention (RFC 9449), but the gateway does not currently verify them. A proof intended for one endpoint could theoretically be presented to another endpoint on the same gateway within the 30-second freshness window.

**Impact is bounded:** proofs are already bound to a specific `agent_id`, `action`, `resource`, and `action_digest`. The jti replay cache (30s TTL) prevents reuse. Endpoint binding (`htm`/`htu` enforcement) is planned for v0.3 once the gateway has a self-URL configuration mechanism for multi-endpoint deployments.

### Dev Mode (`GATEWAY_DEV_MODE=true`)
Setting `GATEWAY_DEV_MODE=true` permits one relaxation:

- **MCP transport auth** — `MCP_AUTH_MODE=none` becomes permitted (without the flag, the server refuses to start in `none` mode).

Dev mode is for local development only. The startup assertion prevents serving with auth disabled without the dev flag.

**DNS rebinding protection** is always enabled regardless of dev mode. Allowed hosts are configured via `MCP_ALLOWED_HOSTS` (comma-separated hostnames). Localhost is always allowed. For Cloud Run, set `MCP_ALLOWED_HOSTS` to the service's FQDN. In production, use `MCP_AUTH_MODE=bearer` or `MCP_AUTH_MODE=iam`.

## LLM Blast Radius Containment

The ADK chat agent is intentionally restricted to **read-only tools**:

| Surface | Tools | Can issue tokens? |
|---------|-------|-------------------|
| ADK Chat (LLM) | get_chain_stats, get_receipt_chain, verify_receipt, get_public_key, Google Search | **No** |
| MCP Server | authorize_action, get_chain_stats, get_receipt_chain, verify_receipt, get_public_key | **Yes** (authorize_action only) |
| REST API | All endpoints including /authorize | **Yes** (POST /authorize only) |

This separation ensures that even a fully compromised chat session (via prompt injection) cannot:
- Issue authorization tokens
- Authorize actions on behalf of agents
- Modify security policies
- Register new agent identities

The chat agent can only inspect and verify — it is an auditor, not an authorizer. A startup assertion in `gateway/agent.py` fails loudly if a privileged tool is accidentally added to the LLM surface.
