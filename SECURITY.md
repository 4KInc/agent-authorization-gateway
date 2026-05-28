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
If the Ed25519 private key is extracted from the Gateway process, an attacker can forge valid tokens and receipts offline. **Mitigation:** Store keys in Cloud KMS or a hardware security module in production. The current implementation generates keys in-memory per instance — acceptable for the hackathon but not for production deployment.

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

1. **Receipt signing key integrity:** The Ed25519 private key has not been exfiltrated.
2. **Anchor sink write-once property:** The Merkle root anchor destination (Cloud Storage with versioning, or the local signed log) is not retroactively rewritable without leaving evidence.
3. **Verifier independence:** The receipt verification code (`gateway/verify.py`) uses only the public key and standard cryptographic operations. It does not trust the Gateway — it verifies against math.

**Important:** Firestore receipts are mutable by any operator with write access to the database. Tamper-evidence does not derive from Firestore — it derives from the Ed25519 signatures on each receipt and the external anchor sink. If a receipt is modified in Firestore, `verify_receipt` will detect the tampering because the signature will not match the modified body. Firestore is a convenience store for querying and display; the cryptographic chain is the source of truth.

If any of the above assumptions are violated, the tamper-evidence guarantee degrades to "detection after the fact" rather than "prevention."

## Cryptographic Choices

| Primitive | Choice | Why |
|-----------|--------|-----|
| Receipt signing | Ed25519 (EdDSA) | Fast, compact (64-byte signatures), no key size debates, mandatory in the Receipt Chain Verification Protocol v0.1 |
| Token signing | Ed25519 (EdDSA) | Asymmetric — resources verify with public key only, no shared secret needed |
| Hash chain | SHA-256 with `prev_receipt` linkage | Standard, well-understood, compatible with Merkle tree construction |
| Merkle tree | SHA-256, RFC 6962 domain separation | Prevents second-preimage attacks on the tree structure |
| Canonicalization | RFC 8785 (JCS subset) | Deterministic JSON serialization for reproducible hashes across languages |
| Token format | JWT with EdDSA signature | Industry-standard token format, verifiable by any JWT library supporting EdDSA |

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
