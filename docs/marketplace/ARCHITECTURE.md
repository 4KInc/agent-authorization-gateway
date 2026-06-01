# Architecture

## Overview

Gate is a cryptographic policy enforcement layer for enterprise AI agents. Every authorization decision — approve or deny — produces an Ed25519-signed, SHA-256 hash-chained, Merkle-anchored receipt that any third party can independently verify without trusting the gateway. The system comprises six collaborating agents deployed as Google Cloud Run services:

1. **Gateway** — deterministic authorization chokepoint (no LLM in the trust path)
2. **Policy Auditor** — asynchronous compliance auditor powered by Gemini 2.5 Pro
3. **Policy Recommender** — pattern-driven policy proposal agent
4. **Incident Investigator** — evidence-synthesis agent for security events
5. **Discovery Coordinator** — A2A agent directory and capability-matching service
6. **Isolator** — automated containment agent triggered on HIGH/CRITICAL incidents

The Gateway is the only agent on the authorization trust path. The five AI agents observe, audit, recommend, investigate, and contain — but never modify policy or authorization state autonomously. This architectural separation ensures that a compromised or hallucinating LLM cannot affect real-time authorization decisions.

## System Diagram

See [docs/architecture.svg](../architecture.svg) for the full system diagram showing all six agents, their data flows, and external dependencies.

```
┌─────────────────────────────────────────────────────────────────┐
│                      Caller Surfaces                            │
│   REST API  │  MCP Server  │  ADK Chat  │  A2A Protocol        │
└──────┬──────┴──────┬───────┴──────┬─────┴───────┬──────────────┘
       │             │              │              │
       └─────────────┴──────┬───────┴──────────────┘
                            ▼
              ┌──────────────────────────┐
              │   Gateway (Deterministic)│  ← Ed25519 signing, policy eval
              │   kid: gateway-hackathon │    hash chain, DPoP verification
              │   -demo-d7cfccc9        │
              └──────────┬───────────────┘
                         │ Signed receipts
                         ▼
              ┌──────────────────────────┐
              │   Cloud Firestore        │  ← tenants/{id}/receipts/
              └──────────┬───────────────┘
                         │
          ┌──────────────┼──────────────────────────┐
          ▼              ▼                           ▼
  ┌───────────┐  ┌──────────────┐  ┌──────────────────────────┐
  │  Auditor  │  │ Recommender  │  │  Discovery Coordinator   │
  │(Gemini)   │  │ (Gemini)     │  │  (Gemini)                │
  └─────┬─────┘  └──────────────┘  └──────────────────────────┘
        │ CONFLICT verdict
        ▼
  ┌───────────────┐
  │  Pub/Sub      │ → auditor-conflicts topic
  └───────┬───────┘
          ▼
  ┌───────────────┐        ┌───────────────┐
  │ Investigator  │──HIGH/─▶   Isolator    │
  │ (Gemini)      │ CRIT   │ (Gemini)      │
  └───────────────┘        └───────────────┘
```

## The Six Agents

### 1. Gateway (Deterministic)

**Purpose:** The single authorization chokepoint. All authorization requests — regardless of surface (REST, MCP, ADK, A2A) — converge to `GatewayService.authorize()`. The Gateway evaluates a deterministic policy (action allowlists, resource scoping, rate limits), signs the resulting receipt with Ed25519, chains it to the previous receipt via SHA-256 hash linkage, and issues a scoped token if the decision is `approve`. Policy is loaded from a YAML file, Firestore, or the built-in demo policy (resolved in that priority order). The action registry and resource registry are persisted in Firestore; when `require_resource_registration` is set in the policy, requests targeting unregistered resources are denied.

| Property | Value |
|---|---|
| Type | Deterministic (no LLM) |
| Signing key kid | `gateway-hackathon-demo-d7cfccc9` |
| Secret Manager secret | `gateway-signing-key` |
| Persistence | `tenants/{id}/receipts/`, `tenants/{id}/metadata/` |
| Triggers | Synchronous per-request |
| Cloud Run services | `agent-auth-gateway` (REST), `agent-auth-gateway-mcp` (MCP), `agent-auth-gateway-adk` (ADK chat), `agent-auth-gateway-a2a` (A2A entrypoint), `agent-auth-gateway-resource` (protected resource) |
| Policy sources | YAML file, Firestore, or built-in demo policy (resolved in priority order) |
| Registries | Action registry and Resource registry with Firestore persistence; `require_resource_registration` flag enforced at eval time |

**Endpoints (REST surface):**

| Method | Path | Purpose |
|---|---|---|
| POST | `/authorize` | Evaluate action, sign receipt, issue token |
| POST | `/agents/register-challenge` | Issue single-use nonce for proof-of-possession (PoP) challenge — step 1/2 |
| POST | `/agents/register` | Submit public key + signed PoP response; Gateway verifies signature before accepting — step 2/2 |
| GET | `/keys` | Published gateway JWK (for offline verification) |
| GET | `/chain` | Receipt chain summary |
| POST | `/verify-receipt` | Verify a receipt's signature and chain linkage (supports partial chains) |
| GET | `/anchors` | List Merkle anchor records |
| GET | `/anchors/verify/{tx_hash}` | Verify a specific on-chain anchor |
| GET | `/health` | Liveness probe |

### 2. Policy Auditor (AI)

**Purpose:** Reads new receipts on a scheduled tick and cross-references each decision against compliance frameworks (OWASP NHI Top 10, NIST AI RMF, NIST SP 800-53) via RAG over a Vertex AI Search corpus. Produces signed audit reports with verbatim citations. Publishes CONFLICT verdicts to Pub/Sub for downstream investigation.

| Property | Value |
|---|---|
| Type | AI (Gemini 2.5 Pro via Vertex AI Model Garden) |
| Signing key kid | `auditor-b96225df` |
| Secret Manager secrets | `gateway-auditor-signing-key`, `gateway-auditor-config` |
| Persistence | `tenants/{id}/audit_reports/`, `tenants/{id}/auditor_state/` |
| Triggers | Cloud Scheduler (`auditor-tick`, `*/5 * * * *`) |
| Cloud Run service | `agent-auth-gateway-auditor` |

| Method | Path | Purpose |
|---|---|---|
| POST | `/audit-tick` | Process batch of unaudited receipts |
| GET | `/audit-reports` | Query audit reports by tenant |
| GET | `/audit-keys` | Published auditor JWK |
| GET | `/health` | Liveness probe |

### 3. Policy Recommender (AI)

**Purpose:** Analyzes patterns across audit reports and proposes policy changes (scope tightening, rate limit adjustments, allowlist modifications). All proposals are stored with `human_review_required: true` — the Recommender never modifies policy autonomously.

| Property | Value |
|---|---|
| Type | AI (Gemini 2.5 Pro via Vertex AI Model Garden) |
| Signing key kid | `recommender-W_Wj5MyPc7nrusSM` |
| Secret Manager secrets | `gateway-recommender-signing-key`, `gateway-recommender-config` |
| Persistence | `tenants/{id}/policy_proposals/` |
| Triggers | Cloud Scheduler (`recommender-tick`, `0 * * * *`) |
| Cloud Run service | `agent-auth-gateway-recommender` |

| Method | Path | Purpose |
|---|---|---|
| POST | `/recommend-tick` | Analyze recent audits, produce proposals |
| GET | `/proposals` | Query proposals by tenant |
| GET | `/recommender-keys` | Published recommender JWK |
| GET | `/health` | Liveness probe |

### 4. Incident Investigator (AI)

**Purpose:** Triggered by CONFLICT audit verdicts (via Pub/Sub) or manual investigation requests. Assembles evidence from receipts, audit reports, agent registrations, and policy proposals to produce human-readable incident reports with severity assessments, timelines, and recommended actions.

| Property | Value |
|---|---|
| Type | AI (Gemini 2.5 Pro via Vertex AI Model Garden) |
| Signing key kid | `investigator-MkX8F8IHaP-CpN7m` |
| Secret Manager secrets | `gateway-investigator-signing-key`, `gateway-investigator-config` |
| Persistence | `tenants/{id}/incident_reports/` |
| Triggers | Pub/Sub push (`auditor-conflicts` topic), HTTP POST |
| Cloud Run service | `agent-auth-investigator` |

| Method | Path | Purpose |
|---|---|---|
| POST | `/investigate` | Pub/Sub push or manual trigger |
| GET | `/incidents` | Query incidents by tenant |
| GET | `/investigator-keys` | Published investigator JWK |
| GET | `/health` | Liveness probe |

### 5. Discovery Coordinator (AI)

**Purpose:** Maintains a directory of A2A-compatible agents, assesses their capabilities using Gemini, and routes natural-language capability queries to matching agents. Does not execute calls to other agents — only identifies matches.

| Property | Value |
|---|---|
| Type | AI (Gemini 2.5 Pro via Vertex AI Model Garden) |
| Signing key kid | `coordinator-uNBU1oMPGc97TTal` |
| Secret Manager secrets | `gateway-coordinator-signing-key`, `gateway-coordinator-config` |
| Persistence | `discovery_coordinator/agents/entries/` |
| Triggers | On-demand HTTP |
| Cloud Run service | `agent-auth-gateway-coordinator` |

| Method | Path | Purpose |
|---|---|---|
| POST | `/discover` | Register an agent by its A2A card URL |
| POST | `/scan` | Batch-scan URLs for A2A agents |
| GET | `/directory` | List all known agents |
| POST | `/route-question` | AI-powered capability matching |
| GET | `/coordinator-keys` | Published coordinator JWK |
| GET | `/health` | Liveness probe |

### 6. Isolator (AI)

**Purpose:** Triggered automatically when the Investigator produces an incident report with severity HIGH or CRITICAL. Executes pre-approved containment playbooks: revoking agent tokens, flagging agents for manual review, and requesting Gateway policy tightening via structured proposals. Like the Recommender, the Isolator never modifies policy directly — it submits containment proposals with `human_review_required: true` and records all actions in Firestore.

| Property | Value |
|---|---|
| Type | AI (Gemini 2.5 Pro via Vertex AI Model Garden) |
| Signing key kid | `isolator-<fingerprint>` |
| Secret Manager secrets | `gateway-isolator-signing-key`, `gateway-isolator-config` |
| Persistence | `tenants/{id}/containment_actions/` |
| Triggers | Pub/Sub push from Investigator (HIGH/CRITICAL incidents), HTTP POST |
| Cloud Run service | `agent-auth-gateway-isolator` |

| Method | Path | Purpose |
|---|---|---|
| POST | `/contain` | Receive incident, execute containment playbook |
| GET | `/containment-actions` | Query containment actions by tenant |
| GET | `/isolator-keys` | Published isolator JWK |
| GET | `/health` | Liveness probe |

## Caller Surfaces (Gateway)

The Gateway exposes four independent surfaces. All four converge to the same `GatewayService.authorize()` method — the authorization logic is implemented once.

| Surface | Cloud Run Service | Base URL | Authentication | Primary Use Case |
|---|---|---|---|---|
| REST API | `agent-auth-gateway` | `https://agent-auth-gateway-...run.app` | DPoP proof (mandatory) | Direct HTTP integration |
| MCP Server | `agent-auth-gateway-mcp` | `https://agent-auth-gateway-mcp-...run.app/mcp` | Bearer token + DPoP proof | LLM agent frameworks (ADK, LangChain, CrewAI) |
| ADK Chat | `agent-auth-gateway-adk` | `https://agent-auth-gateway-adk-...run.app` | Session-based | Conversational interface (read-only chat; authorization via tool calls only) |
| A2A Protocol | `agent-auth-gateway-a2a` | `https://agent-auth-gateway-a2a-...run.app` | OIDC + DPoP proof | Agent-to-agent interoperability (Google A2A SDK v1.1.0) |

A2A is consolidated into each AI agent's REST service rather than a separate transport deployment. Each service exposes its Google A2A agent card at `/.well-known/agent-card.json`.

### MCP Tools

The MCP server exposes 22 tools organized by namespace prefix. Backward-compatible aliases (without prefix) are also registered for tools that existed before namespacing was introduced.

| Namespace | Tool count | Example tools |
|---|---|---|
| `gateway_*` | 8 | `gateway_authorize`, `gateway_register`, `gateway_verify_receipt`, `gateway_get_chain`, `gateway_list_anchors` |
| `auditor_*` | 4 | `auditor_audit_tick`, `auditor_get_reports`, `auditor_get_report`, `auditor_get_keys` |
| `recommender_*` | 4 | `recommender_recommend_tick`, `recommender_get_proposals`, `recommender_get_proposal`, `recommender_get_keys` |
| `investigator_*` | 3 | `investigator_investigate`, `investigator_get_incidents`, `investigator_get_keys` |
| `coordinator_*` | 3 | `coordinator_discover`, `coordinator_directory`, `coordinator_route_question` |

## Data Flow

### Agent Registration (Proof of Possession)

Registration requires a two-step challenge-response proving the registrant controls the private key:

1. **Agent requests challenge.** `POST /agents/register-challenge` returns a single-use nonce (60-second TTL).
2. **Agent signs challenge.** The agent builds a canonical message binding the nonce, agent_id, and public key (JCS canonicalization), then signs it with the corresponding Ed25519 private key.
3. **Agent registers with proof.** `POST /agents/register` with the public key and the signed proof. The Gateway verifies the signature against the submitted public key before accepting the registration.

This prevents registering keys you don't control. All customer agent registrations go through this flow. The six system agents (Gateway, Auditor, Recommender, Investigator, Coordinator, Isolator) use deployment-managed identity via Secret Manager with service-specific kid prefixes — they do not register through the agent registry because their signing kids use a different namespace than the registry's `agent-` prefix. Unifying the two namespaces is a v1.0 roadmap item.

### Authorization Flow

1. **Agent prepares DPoP proof.** The agent computes an `action_digest` (SHA-256 of the JCS-canonicalized action intent), then signs a JWT binding its registered Ed25519 key to that digest. The JWT includes a fresh JTI and timestamp.
2. **Surface authentication.** The chosen surface authenticates the transport (bearer token for MCP, OIDC for A2A, none for REST — REST relies solely on DPoP).
3. **Gateway verifies DPoP proof.** Checks signature against the agent's registered public key, validates freshness (30-second window), checks JTI for replay, and verifies the `action_digest` matches the request parameters.
4. **Gateway evaluates policy.** Four deterministic rule types: action allowlist (action registry), resource scope (allow/deny patterns against resource registry), per-agent rate limiting, and resource registration enforcement (if `require_resource_registration` is set, unregistered resources are denied).
5. **Gateway signs receipt.** Creates a Receipt object with the decision, reason codes, policy version hash, request digest, and `prev_receipt` hash linkage. Signs the JCS-canonicalized receipt body with Ed25519. Computes the SHA-256 receipt hash.
6. **Gateway persists receipt (atomic).** The receipt is written to Firestore before any response is returned. If persistence fails, no token is issued — this is a hard guarantee.
7. **Gateway issues token (if approved).** A 60-second Ed25519-signed JWT with the action digest, JTI (bound to the receipt), and audience scope.
8. **Resource verifies token independently.** The protected resource fetches the gateway's public key from `/keys` and verifies the token's signature, expiration, and action digest — without calling the gateway.

### Six-Agent Pipeline: From Receipt to Containment

The six agents form a reactive pipeline. The Gateway produces signed receipts; each downstream agent reads artifacts from the previous stage and produces its own signed output. The full pipeline — from authorization decision to automated containment — runs without human intervention.

```
Customer Agent
    │ authorize request + DPoP proof
    ▼
┌──────────┐  signed receipt   ┌──────────┐  CONFLICT verdict   ┌──────────────┐
│ GATEWAY  │ ───────────────▶  │ AUDITOR  │ ──── Pub/Sub ────▶  │ INVESTIGATOR │
│(determ.) │  (Firestore)      │(Gemini)  │  auditor-conflicts  │  (Gemini)    │
└──────────┘                   └──────────┘                     └──────┬───────┘
                                    │                                  │
                                    │ CONFLICT pattern                 │ HIGH/CRITICAL
                                    ▼                                  ▼
                              ┌─────────────┐                   ┌──────────┐
                              │ RECOMMENDER │                   │ ISOLATOR │
                              │  (Gemini)   │                   │ (Gemini) │
                              └─────────────┘                   └──────────┘
                              policy proposal                   containment
                              (human review)                    action record

              ┌─────────────┐
              │ COORDINATOR │  (independent — A2A directory + capability routing)
              │(Gemini+det.)│
              └─────────────┘
```

### Audit Flow (Auditor)

1. **Auditor reads new receipts.** Cloud Scheduler triggers `/audit-tick` every 5 minutes. The Auditor reads unaudited receipts (above its Firestore checkpoint) in batches of 10.
2. **RAG against compliance corpus.** For each receipt, the Auditor formulates at least two search queries (NIST SP 800-53 + OWASP NHI Top 10) against a Vertex AI Search data store containing the compliance PDFs.
3. **Gemini reasons about alignment.** The LLM receives the receipt facts and the retrieved passages, then assesses whether the deterministic decision aligns with the compliance guidance.
4. **Auditor signs and persists audit report.** The verdict (ALIGNED, CONFLICT, or INSUFFICIENT_EVIDENCE), rationale, and verbatim citations are signed with the Auditor's Ed25519 key and stored in Firestore.
5. **CONFLICT publishes to Pub/Sub.** If the verdict is CONFLICT, the Auditor publishes `{tenant, audit_id}` to the `auditor-conflicts` Pub/Sub topic. This is the trigger for the downstream investigation pipeline.

### Investigation Flow (Investigator)

6. **Investigator receives CONFLICT notification.** The `auditor-conflicts-push` subscription pushes to the Investigator's `POST /investigate` endpoint. The Investigator can also be triggered manually via HTTP.
7. **Evidence gathering.** The Investigator fetches the triggering audit report, the underlying receipt, the agent's registration history, and the agent's recent activity (last 24 hours of receipts). It cross-references data sources that no single other agent has access to.
8. **Gemini synthesizes incident report.** The LLM produces a structured incident report with: executive summary, chronological timeline with evidence IDs, agents involved (actor/affected/witness with registration status), compliance impact assessment, root cause hypothesis, and recommended actions.
9. **Severity assignment.** The Investigator classifies the incident: CRITICAL (unauthorized access succeeded or system integrity compromised), HIGH (attack pattern or CONFLICT on high-value resource), MEDIUM (CONFLICT on low-value resource), LOW (anomaly worth recording), or INFO (no actual incident).
10. **Investigator signs and persists incident report.** The full report is signed with the Investigator's Ed25519 key and stored in Firestore.

### Containment Flow (Isolator)

11. **Isolator triggered on HIGH/CRITICAL.** If the Investigator assigns severity HIGH or CRITICAL, it immediately POSTs the incident report to the Isolator's `POST /isolate` endpoint via authenticated service-to-service HTTP call.
12. **Gemini analyzes containment options.** The Isolator evaluates the incident and determines the appropriate containment action for each identified rogue agent:
    - **REVOKE_REGISTRATION**: Removes the agent's public key from the Gateway registry. All future authorization requests from this agent are rejected. Used for clearly rogue agents.
    - **RATE_LIMIT_ZERO**: Recommends setting the agent's rate limit to zero. Requires manual policy update (the Isolator cannot modify policy directly). Used when the agent is unregistered or revocation is not possible.
    - **MONITOR_ONLY**: Flags the agent for human review without taking enforcement action. Used for ambiguous cases where the incident may be a false positive.
13. **Containment execution.** For REVOKE_REGISTRATION, the Isolator calls `DELETE /agents/{agent_id}` on the Gateway. For RATE_LIMIT_ZERO and MONITOR_ONLY, the action is recorded as a recommendation.
14. **Isolator signs and persists isolation record.** Every containment action — whether executed or recommended — is signed with the Isolator's Ed25519 key and stored in Firestore at `tenants/{tenant}/isolation_records/{isolation_id}`.

### Recommendation Flow (Recommender)

15. **Recommender analyzes audit patterns.** Cloud Scheduler triggers `/recommend-tick` hourly. The Recommender reads recent audit reports and groups them by pattern: repeated CONFLICTs on the same action/resource, frequent denials, or borderline passes.
16. **Gemini proposes policy changes.** For patterns that warrant attention (3+ CONFLICTs of the same shape, high-frequency denials), the Recommender produces specific policy change proposals with diffs, rationale, and supporting citations from audit reports.
17. **Recommender signs and persists proposal.** Each proposal is signed, marked `human_review_required: true`, and stored in Firestore. The Recommender never modifies policy directly.

### Discovery Flow (Coordinator)

18. **Coordinator maintains agent directory.** The Coordinator discovers agents via A2A protocol (fetching `/.well-known/agent-card.json`), manual registration (`POST /discover`), or batch scanning (`POST /scan`).
19. **Gemini assesses capabilities.** For each discovered agent, the Coordinator uses Gemini to summarize the agent's capabilities from its A2A card.
20. **Capability routing.** On `POST /route-question`, the Coordinator matches a natural-language question against the directory and returns the most capable agent(s) with confidence scores. The Coordinator does NOT execute calls — it only identifies matches.

### Key architectural properties of the pipeline

- **No single point of failure.** Each agent operates independently. If the Auditor is down, receipts accumulate and are audited on the next tick. If the Isolator is down, incidents are still recorded — containment can be triggered manually later.
- **Every artifact is independently signed.** Receipts (Gateway key), audit reports (Auditor key), incident reports (Investigator key), isolation records (Isolator key), policy proposals (Recommender key), and discovery entries (Coordinator key) are each signed by the producing agent's own Ed25519 key. No agent can forge another agent's output.
- **AI never touches the authorization trust path.** The Gateway is deterministic. The five AI agents observe, audit, recommend, investigate, and contain — but the Gateway is the only component that can issue tokens or sign receipts. A compromised or hallucinating LLM cannot affect real-time authorization decisions.
- **The Isolator is the only agent that acts.** All other agents produce reports for humans. The Isolator is the only agent authorized to take automated enforcement actions (revoking registrations). Even then, every action is logged in a signed record.

## Persistence Layer

All persistent state is in Cloud Firestore under a per-tenant namespace:

| Collection Path | Document Schema | Written By |
|---|---|---|
| `tenants/{id}/receipts/{hash_prefix}` | `{body: {v, tenant, seq, ts, request_digest, policy_version, decision, reasons, prev_receipt, token_jti?}, sig: {alg, kid, value}, receipt_hash, _meta: {agent_id, action, resource}}` | Gateway |
| `tenants/{id}/audit_reports/{audit_id}` | `{body: {audit_id, receipt_seq, verdict, rationale, citations[], audited_at}, sig: {alg, kid, value}}` | Auditor |
| `tenants/{id}/policy_proposals/{proposal_id}` | `{body: {proposal_id, trigger, proposed_change, confidence, proposed_at, human_review_required}, sig: {alg, kid, value}}` | Recommender |
| `tenants/{id}/incident_reports/{incident_id}` | `{body: {incident_id, severity, narrative, evidence_references, trigger_type}, sig: {alg, kid, value}}` | Investigator |
| `tenants/{id}/auditor_state/checkpoint` | `{last_audited_seq: int}` | Auditor |
| `tenants/{id}/metadata/keys` | `{tenant, keys: [JWK]}` | Gateway |
| `tenants/{id}/metadata/agent_registry` | `{agents: {agent_id: {public_key, registered_at}}}` | Gateway |
| `tenants/{id}/metadata/action_registry` | `{actions: {action_id: {allowed_resources, rate_limit, registered_at}}}` | Gateway |
| `tenants/{id}/metadata/resource_registry` | `{resources: {resource_id: {patterns, registered_at}}}` | Gateway |
| `tenants/{id}/metadata/stats` | `{total_requests, approvals, denials, ...}` | Gateway |
| `tenants/{id}/anchors/{tx_prefix}` | `{merkle_root, tx_hash, block_number, receipt_range}` | Gateway |
| `tenants/{id}/isolation_records/{isolation_id}` | `{body: {isolation_id, tenant, agent_id, severity, trigger, reason, actions_taken[], isolated_at, isolator_kid}, signature}` | Isolator |
| `discovery_coordinator/agents/entries/{url_hash}` | `{agent_card_url, agent_card, trust_level, health_status, ai_assessed_capabilities}` | Coordinator |

## Cryptographic Substrate

- **Signing:** Ed25519 (EdDSA) per agent. Each agent has an independent keypair stored in Secret Manager. The Gateway, Auditor, Recommender, Investigator, Coordinator, and Isolator each publish their public key via a `/keys` or `/<agent>-keys` endpoint.
- **Hash chain:** SHA-256. Each receipt's `prev_receipt` field contains the hash of the previous receipt, forming an append-only chain. The genesis receipt uses a zero hash.
- **Canonical JSON:** RFC 8785 (JSON Canonicalization Scheme) ensures deterministic byte-level representation for hashing and signing.
- **Merkle anchoring:** RFC 6962-style Merkle tree over receipt hashes. Roots are periodically anchored to Base L2 mainnet (every 10 receipts or hourly).
- **DPoP proofs:** RFC 9449-inspired proof of possession. Each authorization request includes a fresh, signed JWT binding the agent's identity to the specific action via `action_digest`.
- **Key management:** One Secret Manager secret per system agent (6 total). Customer agents generate and register their own Ed25519 keys via the PoP registration flow. No ephemeral key generation in production. No key rotation during the current release cycle (v0.5).

## Cloud Run Services

Ten services are deployed. Each AI agent service also serves its A2A agent card at `/.well-known/agent-card.json`.

| Service name | Agent | Role |
|---|---|---|
| `agent-auth-gateway` | Gateway | REST authorization API, token issuance, receipt chain |
| `agent-auth-gateway-mcp` | Gateway | MCP server (22 tools, 5 namespaces) |
| `agent-auth-gateway-adk` | Gateway | ADK conversational chat interface (read-only) |
| `agent-auth-gateway-a2a` | Gateway | A2A protocol entrypoint |
| `agent-auth-gateway-auditor` | Policy Auditor | Compliance RAG auditing, Pub/Sub CONFLICT publisher |
| `agent-auth-gateway-recommender` | Policy Recommender | Pattern-driven policy proposal generation |
| `agent-auth-investigator` | Incident Investigator | Evidence-synthesis, incident reports |
| `agent-auth-gateway-coordinator` | Discovery Coordinator | A2A agent directory, capability routing |
| `agent-auth-gateway-isolator` | Isolator | Automated containment on HIGH/CRITICAL incidents |
| `agent-auth-gateway-resource` | — | Protected resource demo (token verification) |

## External Dependencies

All infrastructure is Google Cloud. No third-party SaaS sits on any trust path.

| Service | Purpose |
|---|---|
| Cloud Run | Hosts all 10 Cloud Run services (scale-to-zero, managed TLS) |
| Cloud Firestore | Receipt, audit, proposal, and incident persistence |
| Vertex AI Search | RAG retrieval over OWASP/NIST compliance PDFs |
| Vertex AI Model Garden (Gemini 2.5 Pro) | Reasoning for Auditor, Recommender, Investigator, Coordinator |
| Secret Manager | Ed25519 private keys and agent configuration |
| Pub/Sub | Event-driven CONFLICT notification (Auditor → Investigator) |
| Cloud Scheduler | Periodic ticks for Auditor (5 min) and Recommender (hourly) |
| Cloud Build + Artifact Registry | Container image builds and storage |
| IAM | Service-to-service access control |
| Base L2 Mainnet | On-chain Merkle root anchoring (optional, async) |

## Failure Modes and Safeguards

**Firestore unreachable:** Receipt persistence fails → no token is issued, even if the policy evaluation returned `approve`. This is the atomic-persistence guarantee. The Gateway returns an error rather than issuing a token without a persisted receipt.

**Secret Manager unreachable:** The signing key cannot be loaded → the Gateway refuses to start. The startup self-check (`startup_check.py`) performs a sign-verify roundtrip and fails hard if the key is unavailable.

**Pub/Sub publish failure:** If a CONFLICT audit report cannot be published to `auditor-conflicts`, the failure is logged but the audit report is still persisted. The Investigator will not auto-fire, but the CONFLICT is visible in the audit reports collection and can be investigated manually.

**Gemini API unavailable:** The five AI agents degrade to ERROR verdicts, empty proposal lists, or skipped containment runs. Authorization continues unaffected because the Gateway is deterministic and does not invoke any model.

**Cloud Run cold start:** The Gateway resumes its receipt chain from Firestore on startup, continuing from the maximum persisted sequence number. Chain integrity is maintained across restarts.

**Partial chain verification:** `verify_chain` accepts a `start_seq` parameter, allowing verification of a contiguous sub-range of the chain without requiring all preceding receipts. The genesis of the sub-range is treated as the anchor point, and hash linkage is validated forward from there.
