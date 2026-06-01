# Model Usage

## Overview

Gate uses Gemini 2.5 Pro for all AI reasoning. Five of the six agents use models; the Gateway is entirely deterministic and does not invoke any model. This architectural separation ensures that no model sits on the authorization trust path — all real-time authorization decisions are made by deterministic policy evaluation, and model-powered agents operate asynchronously on the resulting audit trail.

All model calls are routed through Vertex AI's Model Garden (`us-central1-aiplatform.googleapis.com`), powered by Gemini 2.5 Pro. Model Garden routing provides enterprise-grade controls: customer-controlled region for model inference, VPC Service Controls support, customer-managed encryption keys (CMEK), and unified billing through GCP. The `GOOGLE_GENAI_USE_VERTEXAI=TRUE` environment variable on each agent service activates Vertex routing through the ADK.

## Models in Use

| Agent | Model | Provider | Routing | Mode | Purpose |
|---|---|---|---|---|---|
| Gateway | **None** | — | — | — | All authorization decisions are deterministic (policy rules, no LLM) |
| Auditor | Gemini 2.5 Pro | Google | Vertex AI Model Garden | Async, batched (10/tick) | Compliance audit reasoning with RAG citations |
| Recommender | Gemini 2.5 Pro | Google | Vertex AI Model Garden | Async, scheduled (hourly) | Pattern detection and policy proposal drafting |
| Investigator | Gemini 2.5 Pro | Google | Vertex AI Model Garden | Reactive, event-driven | Evidence synthesis and incident report assembly |
| Coordinator | Gemini 2.5 Pro | Google | Vertex AI Model Garden | On-demand, per-request | Agent capability assessment and question routing |
| Isolator | Gemini 2.5 Pro | Google | Vertex AI Model Garden | Reactive, event-driven | Incident severity analysis and containment recommendation |

### Model Garden Routing

Gemini 2.5 Pro is accessed via Vertex AI's Model Garden in the `us-central1` region. This is the same model available through the Google AI API, but accessed through Vertex AI Model Garden's enterprise endpoint (`us-central1-aiplatform.googleapis.com`).

Benefits of Model Garden routing:

- **Single audit point** for all AI model invocations in the Cloud Console Model Garden usage page
- **Customer-controlled region** for inference (data residency compliance)
- **VPC Service Controls** support (network-level isolation)
- **Customer-managed encryption keys (CMEK)** compatible
- **Unified GCP billing** (no separate Google AI API key required)
- **Consistent IAM** (`roles/aiplatform.user` on each agent's service account)

The agents use Google's Agent Development Kit (ADK) which transparently routes to Vertex AI when `GOOGLE_GENAI_USE_VERTEXAI=TRUE` is set in the service environment. Verified in deployment logs: `backend: GoogleLLMVariant.VERTEX_AI`.

## What Data Is Sent to Models

### Auditor

Each model invocation receives:

- **Receipt body:** `agent_id`, `action`, `resource`, `decision`, `reasons` (reason codes), `ts` (timestamp), `policy_version` (SHA-256 hash), `seq` (sequence number). These are opaque metadata strings — see [DATA_PROCESSING.md](./DATA_PROCESSING.md) for PII considerations.
- **Compliance corpus passages:** Verbatim extractive answers returned from Vertex AI Search queries against the OWASP NHI Top 10, NIST AI RMF, and NIST SP 800-53 PDFs. These are passages from public compliance documents.
- **System instruction:** The Auditor's static prompt template (defined in `gateway/auditor/auditor_agent.py`). This is a constant string that does not change per invocation.

### Recommender

Each model invocation receives:

- **Recent audit reports:** Audit report envelopes from the last 24 hours for the tenant, including `verdict`, `rationale`, `citations`, `receipt_seq`, and `audit_id`. Batched — one model call processes all recent reports.
- **Recent proposals:** Existing proposals from the last 7 days, to avoid duplicating recent recommendations.
- **System instruction:** The Recommender's static prompt template (defined in `gateway/recommender/recommender_agent.py`).

### Investigator

Each model invocation receives:

- **Triggering audit report:** The CONFLICT verdict report that triggered the investigation, including rationale and citations.
- **Underlying receipt:** The receipt that the audit report assessed, including action, resource, decision, and reason codes.
- **Agent registration:** Registration status and public key metadata for the agent involved.
- **Recent activity:** Receipts from the last 24 hours involving the same agent.
- **Related policy proposals:** Any proposals referencing the same audit report.
- **System instruction:** The Investigator's static prompt template (defined in `gateway/investigator/investigator_agent.py`).

### Coordinator

Each model invocation receives:

- **Agent directory:** The list of registered agents with their A2A agent cards and AI-assessed capability summaries.
- **User's question:** A natural-language capability query (e.g., "Which agent can verify compliance reports?").
- **System instruction:** The Coordinator's static prompt template (defined in `gateway/coordinator/routing_agent.py`).

## What Data Is NOT Sent to Models

- **Signing keys:** Ed25519 private keys are loaded from Secret Manager into process memory. They are never logged, never serialized, and never included in any model prompt.
- **Other tenants' data:** Each AI agent operates on a single tenant's data per invocation. Cross-tenant data is never mixed in a model prompt.
- **DPoP proofs:** Used for cryptographic verification in the Gateway. Never forwarded to AI agents.
- **Customer billing or account data:** Gate does not process or store any customer billing information.
- **Raw policy files:** The policy object (allowlists, resource scopes, rate limits) is referenced by its SHA-256 hash in receipts but is not sent to models in its raw form.

## Hallucination Controls

Each AI agent's system instruction includes explicit non-fabrication requirements, verified against real deployment outputs:

### Auditor

The instruction mandates: *"If the tool returns [no_relevant_compliance_guidance_found] or [search_unavailable: ...], your verdict MUST be INSUFFICIENT_EVIDENCE."* The Auditor must return `INSUFFICIENT_EVIDENCE` rather than invent citations when Vertex AI Search returns no relevant results. In the current deployed chain, 14 of 338 audit reports (4.1%) returned `INSUFFICIENT_EVIDENCE`, demonstrating the control is active.

### Recommender

The instruction mandates: *"If no patterns warrant a proposal, return an empty array. Do not invent patterns to justify a proposal."* The Recommender must cite specific `audit_report_id` values for every claim in a proposal. The threshold for proposing a change is 3+ CONFLICTs of identical shape. In the current deployment, the Recommender produced 1 proposal from 12 CONFLICT verdicts — it exercised restraint rather than generating proposals for every CONFLICT.

### Investigator

The instruction mandates: *"If evidence is insufficient, say so explicitly in the root_cause_hypothesis. Do not fabricate facts."* and *"Cite specific evidence IDs for every claim in the timeline. Never claim 'the agent did X' without an evidence_id pointing to the receipt that proves it."* The Investigator must mark root cause as uncertain when evidence is ambiguous.

### Coordinator

The routing agent returns a `no_match` result with an explanation when no agent in the directory has the queried capability, rather than fabricating a match.

## Determinism and Reproducibility

Gemini 2.5 Pro is non-deterministic. Re-auditing the same receipt may produce different verdicts. In practice:

- Most variance is between `ALIGNED` and `INSUFFICIENT_EVIDENCE` (the model finds different passages on different runs).
- `CONFLICT` vs `ALIGNED` variance is rare but observed — the same cross-environment access pattern was flagged as CONFLICT in some runs and ALIGNED in others.

This non-determinism is architecturally acceptable because:

1. Each audit report is independently signed with the Auditor's Ed25519 key and timestamped.
2. The receipt being audited is immutable — it does not change between audit runs.
3. Multiple audits of the same receipt are preserved as separate signed artifacts.
4. Material disagreement between audits of the same receipt is itself a meaningful signal — it indicates the decision is on a compliance boundary that warrants human attention.

## Cost Controls

Each agent has bounded model invocation per execution cycle:

| Agent | Invocations per Cycle | Cycle Frequency | Bound |
|---|---|---|---|
| Auditor | 1 per receipt (RAG + reasoning in one call) | Every 5 minutes, 10 receipts/tick max | ≤ 2,880 calls/day |
| Recommender | 1 per tick (batched over all recent audits) | Hourly | ≤ 24 calls/day |
| Investigator | 1 per CONFLICT verdict (evidence + reasoning in one call) | Event-driven | Proportional to CONFLICT rate |
| Coordinator | 1 per routing query | On-demand | Proportional to query volume |

No agent makes recursive or chained model calls. No agent has a model loop. Each invocation is a single request-response cycle with the model.

The Auditor's `MAX_PER_TICK` environment variable (default: 10) limits the batch size per tick. At 10 receipts per tick × 288 ticks per day × ~$0.01 per Gemini call, the Auditor's model cost is approximately $30/day at full throughput.

## Human-in-the-Loop Requirements

**Policy proposals (Recommender):** All proposals are stored with `human_review_required: true`. The Recommender never modifies the Gateway's policy. A human policy administrator reviews proposals in the dashboard and decides whether to implement them.

**Incident reports (Investigator):** Reports include recommended actions with priority levels (IMMEDIATE, SHORT_TERM, LONG_TERM) but no actions are taken automatically. The customer's security team decides which actions to execute.

**Audit reports (Auditor):** CONFLICT verdicts trigger further investigation via Pub/Sub but do not modify policy, revoke agent credentials, or block authorization decisions. The Gateway continues to operate based on its deterministic policy regardless of audit verdicts.

**Agent matches (Coordinator):** The Coordinator recommends agents for a capability query but does not invoke the matched agent on the caller's behalf.

## Model Risk Surface

AI agents in Gate do **not** sit on the authorization trust path. The architectural separation means:

**What a compromised model can do:**
- Produce misleading audit reports (false ALIGNED for a genuine policy violation, or false CONFLICT for a legitimate decision)
- Generate inappropriate policy proposals (proposing to weaken security controls)
- Produce misleading incident reports (misattributing root cause, recommending wrong actions)
- Return incorrect agent matches for capability queries

**What a compromised model cannot do:**
- Approve or deny an authorization request (decisions are deterministic)
- Issue or revoke tokens (token signing uses the Gateway's Ed25519 key, not model output)
- Modify the receipt chain (receipts are signed and hash-chained)
- Modify the policy (policy changes require human action)
- Access signing keys (keys are in process memory, not in model context)
- Access other tenants' data (tenant isolation is enforced at the data layer)

**Detection:** Model compromise is detectable because all AI agent outputs are signed artifacts. A false ALIGNED verdict for a receipt that clearly violates policy would be visible to any human reviewer who reads the receipt alongside the audit report. Out-of-band verification (reading receipts directly, cross-referencing with the compliance corpus) would reveal the misalignment.

**Resilience:** Authorization continues to operate correctly even if all five AI agents are compromised simultaneously. The Gateway's deterministic policy enforcement is independent of model outputs. The AI agents provide visibility and recommendations — they do not provide enforcement.

## Audit and Review

All model invocations are visible through:

- **Google Cloud Console:** Model Garden usage page showing request counts, token consumption, and latency per model.
- **Cloud Audit Logs:** Request metadata for all API calls (payloads not logged by default).
- **Signed artifacts:** Each AI agent produces a signed output (audit report, proposal, incident report) that serves as indirect evidence of model behavior. The signed output includes the model's reasoning (rationale), citations, and verdict.
- **Cloud Run logs:** Each model invocation is logged with timing and status by the agent service.

Customers requiring payload-level auditability can enable Vertex AI payload logging, which captures full request/response payloads for model calls. This is subject to additional Cloud Logging storage costs.
