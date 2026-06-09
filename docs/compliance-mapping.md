# Regulatory Compliance Mapping

This document maps specific regulatory requirements to Gate controls and evidence artifacts. It is intended for compliance officers, auditors, and enterprises evaluating Gate for deployment in regulated industries.

**Last updated:** 2026-06-08

---

## Mapping Table

| Regulation | Article / Section | Requirement Summary | Gate Control | Evidence Artifact |
|------------|-------------------|---------------------|--------------|-------------------|
| **EU AI Act** | Article 12 (Automatic Recording) | High-risk AI systems shall be designed to automatically record events ("logs") relevant to identifying risks and substantial modifications throughout the lifecycle. | Every authorization decision (approve and deny) produces a signed receipt linked into a hash chain. The chain is continuous, covering the full lifecycle of agent operations. | Receipt chain (`GET /chain`), Audit Packet export with hash chain continuity verification. |
| **EU AI Act** | Article 13 (Transparency) | High-risk AI systems shall be designed to ensure their operation is sufficiently transparent to enable users to interpret the system's output and use it appropriately. | Signed audit reports explain each authorization decision in natural language, citing applicable compliance frameworks. Public keys are available at `GET /keys` for independent verification. | Signed audit reports (Auditor agent), public key JWKs, receipt verification tools (`verify_receipt`, `verify_chain`). |
| **DORA** | Article 11 (ICT-related incident management — audit trails) | Financial entities shall establish appropriate procedures and policies for ICT audit trails, ensuring data integrity, confidentiality, and availability. | Tamper-evident hash chain with Ed25519 signatures on every receipt. Merkle roots anchored to Base L2 mainnet provide an external, immutable audit trail outside the operator's infrastructure. | Receipt chain with `prev_receipt` linkage, Merkle anchor proofs with Base L2 transaction hashes (`GET /anchors`), BaseScan-verifiable on-chain calldata. |
| **HIPAA** | Section 164.312(b) (Audit Controls) | Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information. | Per-decision receipts record the agent identity, action, resource, policy version, and decision for every authorization attempt. Continuous attestation via the Auditor agent flags anomalous patterns. | Individual receipts with full decision context, Auditor compliance reports, Investigator incident reports for flagged sequences. |
| **SEC** | Rule 17a-4(f) (WORM Storage) | Records required to be maintained and preserved shall be stored in a non-rewriteable, non-erasable format (Write Once, Read Many). | Base L2 on-chain anchoring commits Merkle roots as EVM calldata. Once included in a finalized Base block, the data is immutable — it cannot be altered or deleted by the Gate operator, GCP, or any other party. | Anchor records with `tx_hash`, `block_number`, and `basescan_url`. Independent verification via any Base RPC endpoint. |
| **NIST AI RMF** | Govern (GV) | Establish policies and processes to manage AI risks. | Policy engine evaluates every authorization request against a declarative YAML policy. Policy versions are hashed and recorded in every receipt for auditability. | `policy_version` field in receipt body (SHA-256 of active policy), policy snapshots in Audit Packet. |
| **NIST AI RMF** | Map (MP) | Identify and document AI system contexts, capabilities, and limitations. | Agent registration with proof-of-possession documents each agent's identity and capabilities. Resource registration maps protected resources to tenants. | Agent registry (`GET /agents`), resource registry, signed registration receipts. |
| **NIST AI RMF** | Measure (MS) | Assess AI system performance and impacts. | Receipt chain provides a complete record of authorization decisions for quantitative analysis (approval rates, denial patterns, policy version transitions). Auditor agent performs continuous compliance measurement. | Chain statistics (`GET /chain/stats`), Auditor compliance reports with framework citations, Recommender policy proposals. |
| **NIST AI RMF** | Manage (MG) | Manage AI risks based on assessment results. | Investigator agent performs deep-dive analysis on flagged sequences. Isolator agent provides automated containment (registration revocation, rate-limit-to-zero) for HIGH/CRITICAL incidents. | Investigator incident reports, Isolator containment receipts in the chain, Recommender policy proposals with `human_review_required=true`. |
| **OWASP NHI Top 10** | NHI1: Improper Offboarding | Non-human identities retain access after decommissioning. | Agent registration with replace semantics. Isolator can revoke registration, immediately invalidating all future authorization attempts. Soft-delete preserves audit history. | Agent registry status, revocation receipts in the chain. |
| **OWASP NHI Top 10** | NHI2: Secret Leakage | Credentials exposed in logs, code, or configuration. | Agents never hold persistent credentials to protected resources. Every action requires a fresh 60-second scoped token. Signing keys are held in GCP Secret Manager, never in environment variables or code. | Token TTL enforcement, Secret Manager IAM audit logs. |
| **OWASP NHI Top 10** | NHI3: Vulnerable Third-Party NHI | Third-party integrations with excessive or unmonitored access. | Per-agent Ed25519 identity with DPoP proof of possession. Each agent is individually registered and authorized. Rate limiting is per-agent. | Agent-scoped receipts, per-agent rate limit configuration, DPoP proof verification. |
| **OWASP NHI Top 10** | NHI5: Overprivileged NHI | Non-human identities with more access than needed. | Declarative YAML policy with action/resource scoping per agent pattern. Tokens are scoped to exactly one action via `action_digest` binding. | Policy rules with agent/action/resource patterns, `action_digest` claim in tokens, Recommender least-privilege proposals. |

---

## How to Use This Document

### For Compliance Officers

1. Identify which regulations apply to your deployment.
2. Find the corresponding rows in the mapping table.
3. Use the "Evidence Artifact" column to identify which Gate outputs satisfy each requirement.
4. Request an Audit Packet export (see `docs/audit-packet-spec.md`) covering the relevant time period.

### For Auditors

1. Request an Audit Packet from the Gate operator.
2. Follow the offline verification procedure in `docs/audit-packet-spec.md` to independently verify all signatures, hash chain continuity, and on-chain anchors.
3. Cross-reference the verified receipts against the regulatory requirements in this mapping.

### For Enterprise Evaluators

This mapping demonstrates that Gate's cryptographic receipt chain, on-chain anchoring, and AI-powered audit agents address requirements across multiple regulatory frameworks simultaneously. A single Gate deployment produces evidence artifacts that satisfy overlapping requirements from different regulators, reducing the compliance burden for multi-regulatory environments.

---

## Scope and Limitations

- This mapping covers Gate's authorization and audit capabilities. It does not cover the security of the protected resources themselves (e.g., database access controls, network segmentation).
- Compliance is a shared responsibility. Gate provides the evidence infrastructure; the deploying organization must ensure policies are correctly configured and reviewed.
- Specific regulatory interpretations may vary by jurisdiction and auditor. This mapping reflects Gate's technical capabilities as of v0.5 and should be reviewed with legal counsel for formal compliance determinations.
