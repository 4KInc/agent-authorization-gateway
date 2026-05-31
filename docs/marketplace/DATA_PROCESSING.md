# Data Processing

## Overview

Gate processes authorization metadata for enterprise AI agents. It stores signed decision records (receipts), compliance audit reports, policy proposals, and incident reports. This document describes what data Gate processes, where it stores it, how long it retains it, who has access, and how it handles deletion requests.

**Key statement:** Gate does not process personal data in any standard interpretation. Agent identifiers, action names, and resource names are opaque metadata strings chosen by the customer. Gate does not inspect, parse, or derive meaning from these strings beyond pattern matching against the configured policy.

## Data Categories

| Category | Stored Where | Retention | Personal Data? | Notes |
|---|---|---|---|---|
| Agent registrations | Firestore (`tenants/{id}/agent_registry/{agent_id}`) | Indefinite | No | Public keys, opaque agent_id strings, proof-of-possession flag |
| Signed receipts | Firestore (`tenants/{id}/receipts/`) | Indefinite | No | Immutable, hash-chained. Deletion breaks chain integrity. |
| Audit reports | Firestore (`tenants/{id}/audit_reports/`) | Indefinite | No | Signed by Auditor. Contains verbatim citations from public compliance PDFs. |
| Policy proposals | Firestore (`tenants/{id}/policy_proposals/`) | Indefinite | No | Signed by Recommender. References audit_report_ids. |
| Incident reports | Firestore (`tenants/{id}/incident_reports/`) | Indefinite | No | Signed by Investigator. Contains narrative and evidence references. |
| Signing keys | Secret Manager | Indefinite | No | Ed25519 private keys. Never logged, never sent to models, never included in API responses. |
| Compliance corpus | Vertex AI Search data store | Indefinite | No | Public documents: OWASP NHI Top 10 (2025), NIST AI RMF 1.0, NIST SP 800-53 Rev 5. |
| Operational logs | Cloud Logging | 30 days (default) | No | Standard Cloud Run request logs. No signed artifacts in logs. |
| Merkle anchor records | Firestore (`tenants/{id}/anchors/`) + Base L2 mainnet | Indefinite (on-chain is permanent) | No | Merkle root hashes. No receipt content on-chain. |

## Personal Data

Gate does **not** store names, email addresses, phone numbers, government identifiers, IP addresses, or any other personal data fields in any of its own data structures.

The fields Gate stores are:

- `agent_id`: an opaque string (e.g., `claude-cs-prod-01`)
- `action`: an opaque verb (e.g., `read`, `query`, `delete`)
- `resource`: an opaque target (e.g., `staging-customer-accounts`)
- `parameters`: an optional opaque JSON object

If a customer chooses to embed personal data in these fields (e.g., `resource: "customer-record:alice@example.com"`), that data flows through Gate as opaque metadata. Gate does not extract, index, or process it differently from any other string. However, it will be included in signed receipts, audit reports, and potentially incident reports — all of which are retained indefinitely by default.

**Recommendation:** Customers in GDPR-sensitive deployments should use non-PII identifiers for all Gate fields. Use internal reference IDs rather than names or email addresses.

## Tenancy Isolation

Each customer's data lives under `tenants/{tenant_id}/` in Firestore. The `tenant_id` is an opaque string chosen by the customer (e.g., `hackathon-demo`, `acme-financial`).

Cross-tenant queries are not exposed at any API endpoint. Each API call that reads tenant data requires the `tenant` parameter, and responses contain only data from that tenant. There is no admin endpoint that returns data across tenants.

The Coordinator's agent directory uses a separate top-level collection (`discovery_coordinator/agents/entries/`) because it indexes agents across organizational boundaries by design.

## Retention

Default retention is **indefinite** for all signed artifacts. This is intentional: the tamper-evidence guarantee of the receipt chain depends on the complete, unbroken chain being available for verification. Deleting a receipt in the middle of the chain breaks the `prev_receipt` hash linkage, making all subsequent receipts unverifiable.

Customers requiring retention limits have three options:

1. **Tenant-per-retention-class.** Create separate tenants for different retention periods (e.g., `acme-90day`, `acme-permanent`). Delete entire tenants when the retention period expires. This is the architecturally recommended approach — it preserves chain integrity within each tenant.

2. **Firestore TTL policies (not recommended for receipts).** Firestore's built-in TTL can be applied to ephemeral collections like `audit_reports` or operational data, but applying TTL to the `receipts` collection breaks the chain integrity guarantee: deleted receipts cause `PREV_LINK_BROKEN` errors when subsequent receipts are verified. If retention limits are required for receipts, prefer option 1 (tenant-per-retention-class) or option 3 (archival and tenant deletion).

3. **Archival and tenant deletion.** Export the tenant's data to Cloud Storage for cold archival, then delete the Firestore collections. The archived data retains cryptographic verifiability (signatures and hash chain are self-contained in the exported documents).

## Deletion

**Tenant-level deletion** is supported and clean. Deleting all subcollections under `tenants/{tenant_id}/` removes all receipts, audit reports, proposals, incidents, and metadata for that tenant. The signing keys (in Secret Manager) are separate and can be retained or rotated independently.

**Per-record deletion** of signed artifacts is technically possible (Firestore supports document deletion) but architecturally discouraged. Deleting a receipt from the middle of the chain causes `PREV_LINK_BROKEN` errors for all subsequent receipts during verification.

**GDPR Article 17 (right to erasure):** If a customer embeds personal data in agent IDs, action names, or resource names, and a data subject requests erasure, the customer must either (a) delete the entire chain, or (b) accept that the signed audit trail retains the data subject's historical action metadata. Gate's architecture surfaces this tension but does not resolve it — it is a customer-side design choice. The recommendation is to avoid embedding PII in Gate fields entirely.

**Agent deregistration:** Removing an agent's public key from the registry prevents future authorization requests from that agent. Historical receipts referencing that agent remain in the chain — they are historical facts, not active credentials.

## Access Control

**Service-to-service:** Cloud Run IAM controls which service accounts can invoke each Cloud Run service. In production deployments, each agent service should have its own service account with minimal required roles.

**Signed artifacts:** Receipts, audit reports, proposals, and incident reports are cryptographically signed. They can be verified offline by anyone with the corresponding agent's public key. This is intentional — the value of a signed receipt is that it can be independently verified without trusting the signer's infrastructure.

**Firestore access:** Restricted to the Gate service accounts. No public Firestore rules. Customers deploy Gate into their own GCP project and control Firestore access through standard IAM.

**Secret Manager:** Signing keys are accessible only to their respective service accounts. The Gateway's signing key is accessible to the Gateway service account; the Auditor's key is accessible to the Auditor service account; and so on.

## Encryption

**At rest:** GCP-managed encryption on all Firestore data and Secret Manager secrets. AES-256 with Google-managed keys by default.

**In transit:** TLS 1.3 on all Cloud Run endpoints. All inter-service communication is over HTTPS. Pub/Sub messages are encrypted in transit by default.

**Customer-managed encryption keys (CMEK):** Customers can apply Cloud KMS CMEK to Firestore and Secret Manager for higher-assurance deployments. This is supported by GCP natively and does not require changes to Gate's code.

## Sub-processors

Google Cloud Platform is the sole data processor. No third-party SaaS sub-processors are involved in any data path.

- Gemini 2.5 Pro model calls are processed within Google's infrastructure via the Google AI API.
- Vertex AI Search queries are processed within Google's infrastructure.
- Cloud Firestore, Secret Manager, Pub/Sub, and Cloud Run are all Google-managed services.

No data leaves Google's infrastructure unless the customer explicitly configures an external integration.

## Data Residency

The default deployment region is `us-central1`. All Cloud Run services, Firestore, Vertex AI Search, Secret Manager, and Pub/Sub resources are provisioned in this region.

Customers requiring data residency in specific jurisdictions can deploy Gate into their own GCP project in their chosen region. The Marketplace listing model supports customer-project deployment. Gate's code is region-agnostic — all region-specific configuration is in the deployment commands, not in the application code.

**Base L2 anchoring:** Merkle root hashes (not receipt content) are anchored to the Base L2 blockchain. This is a public ledger and the data (32-byte SHA-256 hashes) is not considered personal data. Customers who require that no data leave their GCP boundary can disable on-chain anchoring by omitting the `ANCHOR_TO_BASE=true` environment variable.

## Audit Logs

Cloud Audit Logs are enabled on all Gate services by default. Customers have full access to:

- **Admin Activity logs:** Service deployments, IAM changes, secret access.
- **Data Access logs:** Firestore reads/writes (if enabled by customer).
- **Cloud Run request logs:** HTTP request metadata for all service endpoints.

These operational audit logs are separate from Gate's signed audit artifacts. Gate's signed receipts and audit reports provide application-level audit evidence; Cloud Audit Logs provide infrastructure-level evidence. Together they provide defense-in-depth for compliance reviews.
