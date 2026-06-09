# Audit Packet Specification v1

An **Audit Packet** is a self-contained, offline-verifiable JSON bundle that captures every authorization decision, audit report, and on-chain anchor proof for a given tenant and time range. It is the primary deliverable for regulatory audits, incident investigations, and compliance attestations.

## Schema

```json
{
  "version": "1",
  "tenant": "hackathon-demo",
  "generated_at": "2026-06-08T12:00:00Z",
  "time_range": {
    "start": "2026-06-01T00:00:00Z",
    "end": "2026-06-08T00:00:00Z"
  },
  "receipts": [
    {
      "body": {
        "v": "1",
        "tenant": "hackathon-demo",
        "seq": "1",
        "ts": "2026-06-01T00:01:00Z",
        "request_digest": "sha256:...",
        "policy_version": "sha256:...",
        "decision": "approve",
        "reasons": [],
        "prev_receipt": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "token_jti": "uuid-...",
        "resource_registration_id": "res-123"
      },
      "sig": {
        "alg": "EdDSA",
        "kid": "gateway-tenant-hexid",
        "value": "base64url-encoded Ed25519 signature"
      },
      "receipt_hash": "sha256:..."
    }
  ],
  "audit_reports": [
    {
      "report_id": "audit-...",
      "receipt_seq": "42",
      "receipt_hash": "sha256:...",
      "verdict": "ALIGNED",
      "analysis": "...",
      "frameworks_cited": ["OWASP NHI Top 10", "NIST AI RMF"],
      "generated_at": "2026-06-01T01:00:00Z",
      "sig": {
        "alg": "EdDSA",
        "kid": "auditor-kid",
        "value": "base64url..."
      }
    }
  ],
  "anchor_proofs": [
    {
      "merkle_root": "sha256:...",
      "tx_hash": "0x...",
      "block_number": 46641063,
      "block_timestamp": 1735689600,
      "chain_head_seq": 142,
      "anchored_at": "2026-06-01T02:00:00Z",
      "chain_id": 8453,
      "basescan_url": "https://basescan.org/tx/0x..."
    }
  ],
  "inclusion_proofs": {
    "sha256:receipt_hash_1": {
      "merkle_root": "sha256:...",
      "leaf_index": 0,
      "proof": ["sha256:...", "sha256:..."],
      "anchor_tx_hash": "0x..."
    }
  },
  "public_keys": {
    "gateway": {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "gateway-tenant-hexid",
      "use": "sig",
      "alg": "EdDSA",
      "x": "base64url..."
    },
    "auditor": {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "auditor-kid",
      "use": "sig",
      "alg": "EdDSA",
      "x": "base64url..."
    }
  },
  "policy_snapshots": [
    {
      "policy_version": "sha256:...",
      "effective_from": "2026-06-01T00:00:00Z",
      "rules_summary": "3 rules: allow read on staging-database for analytics agents, deny write on production-*, allow query on analytics-warehouse for all registered agents"
    }
  ],
  "metadata": {
    "receipt_count": 142,
    "approval_count": 120,
    "denial_count": 22,
    "anchor_count": 15,
    "chain_integrity": "PASS",
    "generator": "gate-audit-packet-v1"
  }
}
```

## Field Reference

### Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | Schema version. Always `"1"` for this spec. |
| `tenant` | string | Tenant identifier scoping all data in the packet. |
| `generated_at` | string (ISO 8601) | Timestamp when the packet was generated. |
| `time_range` | object | Start and end timestamps bounding the receipts in this packet. |
| `receipts` | array | Complete receipt envelopes (body + sig + receipt_hash) within the time range. |
| `audit_reports` | array | Signed audit reports referencing receipts in this packet. |
| `anchor_proofs` | array | On-chain anchor records with transaction hashes for the covered period. |
| `inclusion_proofs` | object | Mapping from receipt_hash to Merkle inclusion proof and anchor reference. |
| `public_keys` | object | JWKs for all signing keys referenced by receipts and audit reports. |
| `policy_snapshots` | array | Policy versions referenced by receipts, with summaries. |
| `metadata` | object | Aggregate statistics and integrity status. |

### metadata.chain_integrity

The `chain_integrity` field is computed by the generator at export time:

| Value | Meaning |
|-------|---------|
| `PASS` | Every receipt's `prev_receipt` matches the predecessor's `receipt_hash`, and every signature verifies against the included public key. |
| `FAIL` | At least one chain link or signature verification failed. The packet includes the data as-is for forensic analysis. |

## Offline Verification Procedure

An auditor receiving an Audit Packet can verify it without any network access or trust in the Gate operator:

### Step 1: Verify Receipt Signatures

For each receipt in `receipts`:

1. Extract `body` and canonicalize it using RFC 8785 (JCS).
2. Compute `SHA-256(canonical_bytes)` and confirm it matches `receipt_hash`.
3. Look up the signing key from `public_keys` using `sig.kid`.
4. Verify the Ed25519 signature (`sig.value`) over the canonical bytes using the public key.

If any receipt fails, mark the packet as tampered.

### Step 2: Verify Hash Chain Continuity

1. Sort receipts by `body.seq` (numeric).
2. Confirm the first receipt's `prev_receipt` is the null hash (`sha256:` + 64 zeros) or matches a known checkpoint.
3. For each subsequent receipt, confirm `prev_receipt` equals the previous receipt's `receipt_hash`.

Any break indicates a missing or tampered receipt.

### Step 3: Verify Merkle Inclusion Proofs

For each entry in `inclusion_proofs`:

1. Compute the Merkle leaf: `SHA-256("BI_RECEIPT_LEAF_V1" || 0x00 || receipt_hash_bytes)`.
2. Walk the proof path (sibling hashes) up to the root using `SHA-256("BI_RECEIPT_NODE_V1" || 0x00 || left || right)`.
3. Confirm the computed root matches the `merkle_root` in the referenced anchor proof.

### Step 4: Verify On-Chain Anchors

For each entry in `anchor_proofs`:

1. Query any Base L2 RPC endpoint: `eth_getTransactionByHash(tx_hash)`.
2. Confirm the transaction's `input` (calldata) matches the `merkle_root` (hex-encoded, without the `sha256:` prefix).
3. Confirm `block_number` and `block_timestamp` match the on-chain values.

This step requires only a Base RPC endpoint. No trust in the Gate operator is required.

### Step 5: Verify Audit Report Signatures

For each audit report in `audit_reports`:

1. Look up the auditor's public key from `public_keys` using `sig.kid`.
2. Verify the Ed25519 signature over the report body.
3. Confirm the referenced `receipt_hash` exists in the `receipts` array.

### Step 6: Cross-Check Metadata

1. Confirm `metadata.receipt_count` matches `len(receipts)`.
2. Confirm `metadata.approval_count` + `metadata.denial_count` equals `metadata.receipt_count`.
3. Confirm `metadata.anchor_count` matches `len(anchor_proofs)`.

## Design Rationale

- **Self-contained**: The packet includes all public keys, so verification requires no network calls to the Gate operator.
- **Tamper-evident**: On-chain anchors provide an external root of trust. Even if the operator generates a fraudulent packet, the Merkle roots will not match what is on-chain.
- **Incrementally verifiable**: An auditor can verify a single receipt, a chain segment, or the entire packet.
- **Format-neutral**: The packet is JSON for maximum interoperability. Binary-optimized formats (CBOR, Protobuf) are on the v2.0 roadmap.
