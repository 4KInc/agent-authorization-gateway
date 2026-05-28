# Receipt Chain Verification Protocol v0.1

## Overview

The Receipt Chain Verification Protocol defines how authorization decisions are recorded as cryptographically signed, hash-chained, Merkle-anchored receipts that any third party can independently verify.

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
| `request_digest` | string | SHA-256 of canonicalized action intent |
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
- `gateway/receipts.py` — Receipt creation and chain management
- `gateway/verify.py` — Independent verification
- `gateway/canonical.py` — JCS canonicalization
- `gateway/merkle.py` — Merkle tree construction
- `gateway/tokens.py` — Ed25519 token issuance
