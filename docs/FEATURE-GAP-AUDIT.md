# Gate Feature Gap Audit

Date: 2026-06-01
Auditor: Claude Code investigation (5 parallel agents)
System version: v0.5 (post-Isolator, 6-agent pipeline)

## Executive summary

Gate's core cryptographic authorization pipeline is solid: Ed25519 receipts, hash-chained audit trail, DPoP proof-of-possession, Merkle anchoring to Base L2, and a working 6-agent Gemini pipeline are all implemented and deployed. The strongest areas are the cryptographic receipt chain, MCP tool discoverability, and the multi-agent architecture. The most material gaps are in **operational maturity** (static health checks, no metrics/tracing, no backup docs), **developer experience** (no SDK, no getting-started tutorial, no docker-compose), **input validation** (unbounded fields enabling DoS), and **competitive positioning** (no comparison against Auth0/Okta/Vanta/Aembit). Most "fix before submission" items are XS-S effort.

---

## Gap Inventory

### Category 1: Core Authorization Functionality

#### Gap 1.1: Time-of-day restrictions
- **What's missing**: No policy rule type for time-window restrictions
- **What's present**: Policy engine is extensible; adding a new rule type is mechanical
- **Severity**: Polish
- **Effort**: S
- **Recommendation**: Document as known limitation
- **Evidence**: `gateway/policy.py:182` — `_KNOWN_RULE_TYPES` has only allowlist, resource_scope, rate_limit
- **Why it matters**: Common enterprise requirement but not critical for hackathon scope

#### Gap 1.2: Geo-restrictions
- **What's missing**: No IP/geo evaluation in policy rules; request IP never extracted in authorize flow
- **What's present**: N/A
- **Severity**: Polish
- **Effort**: M
- **Recommendation**: Defer to v1.0
- **Evidence**: `gateway/api.py:254-319`
- **Why it matters**: Agent-to-agent calls in cloud infra make geo-restriction less relevant

#### Gap 1.3: Decision caching
- **What's missing**: Every authorize call hits full DPoP verification + policy + receipt signing + Firestore
- **What's present**: JWK key cache (5-min TTL), rate limit counters cached in-memory
- **Severity**: Polish
- **Effort**: M
- **Recommendation**: Defer to v1.0 (intentional design — every action gets a unique receipt)
- **Evidence**: `gateway/gateway_service.py:105-218`
- **Why it matters**: Architectural choice, not a bug — caching would break receipt uniqueness guarantee

#### Gap 1.4: Bulk authorization
- **What's missing**: No multi-action authorization in a single request
- **What's present**: Single-action per call, well-defined semantics
- **Severity**: Polish
- **Effort**: M
- **Recommendation**: Defer to v1.0
- **Evidence**: `gateway/api.py:254-319`
- **Why it matters**: Single-action semantics are cleaner for audit trails

#### Gap 1.5: Delegation
- **What's missing**: No mechanism for one agent to grant scope-narrowed authorization to another
- **What's present**: Each agent must independently register and authorize
- **Severity**: Significant
- **Effort**: L
- **Recommendation**: Document as known limitation
- **Evidence**: `SECURITY.md:197`
- **Why it matters**: Multi-agent workflows with coordinator-delegated sub-tasks need each sub-agent independently registered

#### Gap 1.6: Action context binding
- **What's missing**: Receipts don't capture calling user, session, or parent action ID
- **What's present**: `_meta` field stores agent_id/action/resource in Firestore alongside receipt, but not signed into receipt body
- **Severity**: Significant
- **Effort**: S
- **Recommendation**: Document as known limitation
- **Evidence**: `gateway/receipts.py:47-65`
- **Why it matters**: Cannot reconstruct causal chain of delegated actions from receipts alone

#### Gap 1.7: Revocation propagation (60s window)
- **What's missing**: Isolator deletes agent registration but already-issued tokens remain valid until 60s expiry. No token revocation list.
- **What's present**: 60s TTL limits blast radius. Middleware JTI cache prevents reuse. Future DPoP proofs fail after deletion.
- **Severity**: Significant
- **Effort**: M
- **Recommendation**: Document as known limitation (60s TTL is the mitigation)
- **Evidence**: `gateway/isolator/isolator_service.py:144-191`, `gateway/middleware.py:127-135`
- **Why it matters**: Rogue agent has up to 60s continued access after isolation

#### Gap 1.8: Token introspection (RFC 7662)
- **What's missing**: No introspection endpoint for resources to check token validity
- **What's present**: Resources can verify offline using public key from `GET /keys`
- **Severity**: Polish
- **Effort**: S
- **Recommendation**: Defer to v1.0
- **Evidence**: `gateway/api.py` — no `/introspect` endpoint
- **Why it matters**: With 60s tokens and offline verification, introspection is low priority

#### Gap 1.9: Dry-run bypasses auth + pollutes rate limits
- **What's missing**: `/authorize/dry-run` bypasses DPoP verification entirely — anyone can probe policy. Also increments rate counters, polluting real limits.
- **What's present**: Dry-run evaluates policy and returns decision without creating receipt
- **Severity**: Significant
- **Effort**: XS
- **Recommendation**: **Fix before submission**
- **Evidence**: `gateway/api.py:322-342`
- **Why it matters**: Attacker can enumerate the entire policy without authentication

---

### Category 2: Security Posture

#### Gap 2.1: No automated key rotation
- **What's missing**: Signing key loaded once from Secret Manager on startup, no refresh mechanism
- **What's present**: Middleware tries all keys from `/keys` (supports verification of old keys), but issuance has no overlap/transition
- **Severity**: Significant
- **Effort**: M
- **Recommendation**: Document as known limitation
- **Evidence**: `gateway/signing_key.py:26-27`, `docs/marketplace/ARCHITECTURE.md:338`
- **Why it matters**: Key compromise requires downtime to rotate

#### Gap 2.2: No HSM-backed signing
- **What's missing**: Keys are software-only in Secret Manager, no Cloud KMS/HSM
- **What's present**: Secret Manager provides at-rest encryption + IAM access control
- **Severity**: Polish
- **Effort**: L
- **Recommendation**: Defer to v1.0
- **Evidence**: `gateway/signing_key.py:74-76`
- **Why it matters**: HSM prevents key extraction with full runtime access, but adds latency

#### Gap 2.3: No rate limit on registration challenges
- **What's missing**: `/agents/register-challenge` has no rate limiting — attacker can exhaust memory with unlimited challenges
- **What's present**: Challenges are single-use, 60s TTL, crypto-random nonces. But `_challenges` dict grows unboundedly within the 60s window.
- **Severity**: Significant
- **Effort**: S
- **Recommendation**: **Fix before submission**
- **Evidence**: `gateway/api.py:569-573`, `gateway/identity.py:138-162`
- **Why it matters**: Memory exhaustion DoS via challenge flooding

#### Gap 2.4: In-memory-only JTI replay caches
- **What's missing**: JTI caches are per-instance. Multi-instance deployment allows token replay across instances.
- **What's present**: 60s TTL limits exposure. Caches have max sizes (10000 tokens, 5000 proofs).
- **Severity**: Significant
- **Effort**: M
- **Recommendation**: Document as known limitation
- **Evidence**: `gateway/middleware.py:32-33`, `gateway/identity.py:39-40`
- **Why it matters**: Multi-instance scaling weakens replay protection

#### Gap 2.5: MCP_AUTH_TOKEN in plain env vars
- **What's missing**: MCP bearer token passed as Cloud Run env var (visible to anyone with `run.services.get` IAM permission)
- **What's present**: Signing keys use Secret Manager correctly
- **Severity**: Significant
- **Effort**: S
- **Recommendation**: **Fix before submission** (use `--set-secrets` instead of `--set-env-vars`)
- **Evidence**: `serve_combined.py:30`, `README.md:241`
- **Why it matters**: Env vars in Cloud Run revision metadata are visible in console

#### Gap 2.6: Unbounded input fields
- **What's missing**: `parameters: dict` on AuthorizeRequest has no size limit. `UpdatePolicyRequest.rules` accepts unvalidated `list[dict]`. PATCH actions accepts raw dict.
- **What's present**: String fields have min/max length. agent_id has regex validation.
- **Severity**: Significant
- **Effort**: S
- **Recommendation**: **Fix before submission** (add max_length to parameters, validate rule structure)
- **Evidence**: `gateway/api.py:73` (unbounded dict), `api.py:514` (unbounded list)
- **Why it matters**: Request-body DoS via multi-MB payloads

#### Gap 2.7: GET /chain returns unbounded data
- **What's missing**: No pagination on receipt chain endpoint. FirestoreStore.get_chain() loads ALL receipts into memory.
- **What's present**: Resource listing has cursor-based pagination. Anchor records limited to 50.
- **Severity**: Significant
- **Effort**: S
- **Recommendation**: **Fix before submission** (add limit/offset or cursor)
- **Evidence**: `gateway/api.py:434-454`, `gateway/store.py:145-154`
- **Why it matters**: 10,000+ receipts → OOM or timeout on chain retrieval

#### Gap 2.8: CORS allow_origins=["*"]
- **What's missing**: Wide-open CORS on Gateway REST API and demo-agent
- **What's present**: Other services (auditor, investigator, etc.) correctly have no CORS
- **Severity**: Polish
- **Effort**: XS
- **Recommendation**: Document as known limitation (acceptable for hackathon)
- **Evidence**: `gateway/api.py:211-216`
- **Why it matters**: Low real risk since tokens are agent-issued, not browser cookies

#### Gap 2.9: Prompt injection on action/resource fields
- **What's missing**: `action` and `resource` fields accept any string up to 256/512 chars, passed directly into LLM prompts via receipt JSON
- **What's present**: `agent_id` has regex `[a-zA-Z0-9_-]` which prevents injection. But action/resource don't.
- **Severity**: Significant
- **Effort**: S
- **Recommendation**: **Fix before submission** (add regex validation matching agent_id pattern)
- **Evidence**: `gateway/api.py:70-73`, `gateway/auditor/auditor_agent.py:112-113`
- **Why it matters**: Crafted action/resource strings could manipulate auditor verdicts

#### Strength: Logging hygiene
- No signing keys, DPoP proofs, or tokens logged in plaintext anywhere. KIDs logged, not key material. Clean.

---

### Category 3: Operational Maturity

#### Gap 3.1: Health checks are static 200
- **What's missing**: All 6 services return hardcoded success without checking Firestore/Secret Manager/Pub/Sub
- **What's present**: Each has `/health` returning static JSON
- **Severity**: Significant
- **Effort**: S
- **Recommendation**: **Fix before submission**
- **Evidence**: `gateway/api.py:244-251`, all service `*_service.py` health endpoints
- **Why it matters**: Cloud Run liveness probes mask real outages

#### Gap 3.2: No application-level metrics
- **What's missing**: No custom metrics for authorization latency, approve/deny rates, audit verdicts
- **What's present**: Structured JSON logging, Cloud Run built-in request metrics
- **Severity**: Polish
- **Effort**: M
- **Recommendation**: Document as known limitation
- **Evidence**: Zero matches for metrics/prometheus/cloud.monitoring in gateway/
- **Why it matters**: Cannot set SLOs without application metrics

#### Gap 3.3: No distributed tracing
- **What's missing**: No OpenTelemetry. Cross-service requests (Auditor→Investigator via Pub/Sub) have no correlated traces.
- **Severity**: Polish
- **Effort**: M
- **Recommendation**: Defer to v1.0
- **Evidence**: Zero matches for opentelemetry/otel in codebase
- **Why it matters**: Debugging 6-agent cross-service failures requires log timestamp correlation

#### Gap 3.4: No alerting configured
- **What's missing**: No alert policies in code or Terraform
- **Severity**: Polish
- **Effort**: S
- **Recommendation**: Document as known limitation
- **Evidence**: No alert config files found
- **Why it matters**: HIGH/CRITICAL incidents have no path to human pager

#### Gap 3.5: No backup/restore procedure
- **What's missing**: No documented Firestore backup/restore process
- **What's present**: `scripts/snapshot-firestore-state.py` exists but no restore counterpart
- **Severity**: Significant
- **Effort**: S
- **Recommendation**: Document as known limitation
- **Evidence**: No backup/restore docs in docs/
- **Why it matters**: Firestore is single persistence layer; data loss is unrecoverable

#### Gap 3.6: No docker-compose for local dev
- **What's missing**: No single command to run all 6 agents locally
- **What's present**: Individual `python serve.py`, `python serve_mcp.py`, `adk web` commands
- **Severity**: Significant
- **Effort**: M
- **Recommendation**: **Fix before submission**
- **Evidence**: No docker-compose.yml in repository
- **Why it matters**: Developers evaluating the project need 6 terminal windows + GCP credentials

---

### Category 4: Developer & Integrator Experience

#### Gap 4.1: No SDK package
- **What's missing**: No published `gate-client` Python/TypeScript package
- **What's present**: DPoP helpers exist in `gateway/identity.py` and `demo-agent/main.py` but aren't packaged
- **Severity**: Significant
- **Effort**: M
- **Recommendation**: **Fix before submission** (extract identity.py + canonical.py into pip package)
- **Evidence**: `demo-agent/main.py` reimplements DPoP inline
- **Why it matters**: Every integrator must reimplement DPoP proof construction from the protocol spec

#### Gap 4.2: No LangChain/CrewAI integration examples
- **What's missing**: README claims MCP compatibility with LangChain/CrewAI but provides no examples
- **What's present**: ADK integration examples, demo scripts with raw httpx
- **Severity**: Significant
- **Effort**: S
- **Recommendation**: **Fix before submission** (one 20-line example per framework)
- **Evidence**: `README.md:110`
- **Why it matters**: Multi-framework claims need evidence

#### Gap 4.3: No "zero to first receipt" tutorial
- **What's missing**: No step-by-step guide from git clone to first signed receipt in 15 minutes
- **What's present**: Extensive docs (protocol.md, system-guide.md, policy.md) but no quick-start walkthrough
- **Severity**: Significant
- **Effort**: S
- **Recommendation**: **Fix before submission**
- **Evidence**: README Quick Start covers running server/tests but not the full flow
- **Why it matters**: Judges and evaluators have limited time

#### Strength: MCP tool discoverability
- All 30+ MCP tools have detailed multi-paragraph docstrings. This is one of the strongest aspects.

---

### Category 5: Compliance Evidence

#### Gap 5.1: No SOC 2 / ISO 27001 control mappings
- **What's missing**: No formal mapping of Gate controls to SOC 2 TSC or ISO 27001 Annex A
- **What's present**: SOC 2 PDF in Vertex AI Search corpus; A2A descriptions mention these frameworks
- **Severity**: Significant
- **Effort**: M
- **Recommendation**: Document as known limitation
- **Evidence**: No mapping files in docs/
- **Why it matters**: Enterprise buyers require explicit control mappings for procurement

#### Gap 5.2: No /.well-known/security.txt
- **What's missing**: No RFC 9116 vulnerability disclosure endpoint. Returns 404.
- **What's present**: SECURITY.md in repo root, `/.well-known/agent.json` proves the mechanism works
- **Severity**: Significant
- **Effort**: XS
- **Recommendation**: **Fix before submission**
- **Evidence**: `curl https://agent-auth-gateway-...run.app/.well-known/security.txt` → 404
- **Why it matters**: Standard enterprise security expectation; absence looks like oversight

#### Gap 5.3: No penetration test report
- **What's missing**: No third-party security testing
- **What's present**: Comprehensive self-authored SECURITY.md threat model (12 threats, mitigations)
- **Severity**: Significant
- **Effort**: XL
- **Recommendation**: Document as known limitation ("Independent security audit planned for v1.0")
- **Evidence**: `SECURITY.md` — thorough but self-authored
- **Why it matters**: Enterprise buyers won't deploy crypto infrastructure without independent audit

#### Gap 5.4: Compliance corpus missing referenced docs
- **What's missing**: Auditor instruction references NIST SP 800-53 but it may not be fully indexed in Vertex AI Search corpus
- **What's present**: OWASP NHI Top 10, NIST AI RMF, SOC 2 TSC in corpus
- **Severity**: Significant
- **Effort**: S (upload PDFs to GCS bucket and re-index)
- **Recommendation**: **Fix before submission**
- **Evidence**: `gateway/auditor/SETUP.md:16-25`, `gateway/auditor/auditor_agent.py:39`
- **Why it matters**: Agent instruction tells LLM to query controls that aren't in the index

---

### Category 6: Customer-Facing Polish

#### Strength: Empty states and loading states
- All pages have contextual empty states with guidance. All use Loader2 spinners. No gaps here.

#### Gap 6.1: Silent error swallowing on list fetches
- **What's missing**: `catch {}` blocks on agent/resource/action/policy list fetches silently hide errors
- **What's present**: Error handling IS present for form submissions
- **Severity**: Polish
- **Effort**: S
- **Recommendation**: **Fix before submission**
- **Evidence**: `agents/page.tsx:569`, `resources/page.tsx:311`, `policies/page.tsx:251`
- **Why it matters**: User with misconfigured backend sees empty list with no explanation

#### Gap 6.2: Policy binding delete has no confirmation
- **What's missing**: Trash icon immediately deletes binding with no confirm dialog
- **What's present**: Resources and actions have inline confirm/cancel pattern
- **Severity**: Polish
- **Effort**: XS
- **Recommendation**: **Fix before submission**
- **Evidence**: `policies/page.tsx:184`
- **Why it matters**: Policy bindings are authorization rules; accidental deletion locks out agents

#### Gap 6.3: No export capability
- **What's missing**: No CSV/JSON export for receipts, audit reports, or proposals
- **What's present**: Private key download proves the pattern is implemented
- **Severity**: Polish
- **Effort**: S
- **Recommendation**: **Fix before submission**
- **Evidence**: No download buttons on receipt chain or audit report views
- **Why it matters**: Compliance teams need to extract evidence for offline review

#### Gap 6.4: No multi-user / account management
- **What's missing**: No authentication, no user roles, no RBAC. Single-operator model.
- **What's present**: Tenant isolation in Firestore data model
- **Severity**: Significant
- **Effort**: XL
- **Recommendation**: Defer to v1.0
- **Evidence**: Dashboard hardcodes `tenant=hackathon-demo`
- **Why it matters**: Enterprise deployment requires role-based access

---

### Category 7: Multi-Tenancy & Scale

#### Gap 7.1: No per-tenant quotas
- **What's missing**: No limits on agents/resources/receipts per tenant
- **What's present**: Rate limiting per-agent exists, but no tenant-level object count limits
- **Severity**: Significant
- **Effort**: M
- **Recommendation**: Document as known limitation
- **Evidence**: `gateway/identity.py:89-91` (unbounded dict), `gateway/store.py:131-136` (unbounded writes)
- **Why it matters**: Single tenant can exhaust Firestore quotas

#### Gap 7.2: Hardcoded single tenant
- **What's missing**: REST API hardcodes `tenant="hackathon-demo"`. No admin API for multi-tenant management.
- **What's present**: Firestore data model IS tenant-scoped. Policy differs per tenant in Firestore.
- **Severity**: Significant
- **Effort**: M
- **Recommendation**: Document as known limitation
- **Evidence**: `gateway/api.py:49`
- **Why it matters**: Cannot onboard second tenant without code change

#### Gap 7.3: get_chain() loads all receipts into memory
- **What's missing**: `FirestoreStore.get_chain()` streams ALL receipts, no pagination. OOM at ~10K receipts.
- **What's present**: Resource listing has cursor-based pagination
- **Severity**: Significant
- **Effort**: M
- **Recommendation**: Document as known limitation
- **Evidence**: `gateway/store.py:145-154`
- **Why it matters**: Chain verification unusable at production receipt volumes

---

### Category 8: AI Agent Capabilities

#### Gap 8.1: Investigator can't access agent registration provenance
- **What's missing**: `get_agent_registration` tool only returns registered/unregistered. No timestamp, card verification status, liveness results.
- **What's present**: Registration API stores this data but investigator tool can't retrieve it
- **Severity**: Significant
- **Effort**: S
- **Recommendation**: **Fix before submission**
- **Evidence**: `gateway/investigator/evidence_tools.py:39-48`
- **Why it matters**: Critical evidence missing when investigating rogue agents

#### Gap 8.2: No quarantine reversal workflow
- **What's missing**: Once Isolator revokes registration, no human-review interface to lift quarantine. No "quarantine" status distinct from "revoked."
- **What's present**: Isolation records are signed and stored. Agent could re-register but loses link to isolation.
- **Severity**: Significant
- **Effort**: M
- **Recommendation**: Document as known limitation
- **Evidence**: `gateway/isolator/isolator_service.py:144-192`
- **Why it matters**: False positive isolations (LLM non-determinism) have no recovery path

#### Gap 8.3: No AI agent disagreement handling
- **What's missing**: No protocol for contradictory verdicts (known issue: auditor CONFLICT verdicts are non-deterministic)
- **What's present**: Linear pipeline with no feedback loop or consensus mechanism
- **Severity**: Significant
- **Effort**: L
- **Recommendation**: Document as known limitation
- **Evidence**: `gateway/auditor/auditor_service.py:181-188`, MEMORY.md known issues
- **Why it matters**: Non-deterministic CONFLICTs can trigger unnecessary investigations

#### Gap 8.4: No model fallback
- **What's missing**: All agents hardcode `gemini-2.5-pro`. Outage → silent pipeline degradation (ERROR verdicts, empty proposals, no investigations).
- **What's present**: Error handling exists and logs exceptions
- **Severity**: Significant
- **Effort**: S
- **Recommendation**: Document as known limitation
- **Evidence**: `gateway/auditor/auditor_agent.py:92`, `gateway/investigator/investigator_agent.py:199-201`
- **Why it matters**: Gemini API outage silently degrades entire audit/investigation pipeline

---

### Category 9: Competitive Positioning

#### Gap 9.1: No Auth0/Okta positioning
- **What's missing**: No statement differentiating human identity (Auth0/Okta) from AI agent action authorization (Gate)
- **Severity**: Significant
- **Effort**: XS
- **Recommendation**: **Fix before submission**
- **Evidence**: Zero matches for Auth0/Okta in any .md file
- **Why it matters**: Auth0/Okta are the default mental model for "authorization"

#### Gap 9.2: No Vanta/Drata positioning
- **What's missing**: No statement that Gate produces signed evidence of decisions while Vanta/Drata produce evidence of controls
- **Severity**: Significant
- **Effort**: XS
- **Recommendation**: **Fix before submission**
- **Evidence**: Zero matches for Vanta/Drata in any .md file
- **Why it matters**: Most common compliance tools in target market

#### Gap 9.3: No Anthropic governance positioning
- **What's missing**: No statement on how Gate complements model-level safety (training-time alignment) with infrastructure-level enforcement (runtime proof)
- **Severity**: Significant
- **Effort**: XS
- **Recommendation**: **Fix before submission**
- **Evidence**: Zero matches for Anthropic in any .md file
- **Why it matters**: Most visible company in agent safety; complementarity signals ecosystem awareness

#### Gap 9.4: No build-vs-buy section
- **What's missing**: No doc explaining what an internal team would need to build from scratch
- **What's present**: README comparison table covers 2 open-source projects but not enterprise alternatives
- **Severity**: Significant
- **Effort**: S
- **Recommendation**: **Fix before submission**
- **Evidence**: `README.md:20-27`
- **Why it matters**: Every engineering leader asks "can we just build this ourselves?"

---

### Category 10: Trust Building Artifacts

#### Gap 10.1: No open source strategy statement
- **What's missing**: Repo is private. No statement about open protocol + commercial service positioning.
- **What's present**: Apache-2.0 license. Protocol spec fully documented.
- **Severity**: Significant
- **Effort**: S
- **Recommendation**: **Fix before submission**
- **Evidence**: LICENSE (Apache-2.0), repo is private per project config
- **Why it matters**: Open protocol is Gate's strongest trust signal

#### Gap 10.2: No independent security audit (or plan)
- **What's missing**: No third-party audit. No stated plan for one.
- **What's present**: Comprehensive SECURITY.md threat model
- **Severity**: Significant
- **Effort**: XS (to document plan)
- **Recommendation**: Document as known limitation ("planned for v1.0")
- **Evidence**: `SECURITY.md`
- **Why it matters**: Enterprise buyers require independent audit for crypto infrastructure

#### Gap 10.3: No standards body participation statement
- **What's missing**: No intent to submit protocol to IETF or other standards track
- **What's present**: Protocol is versioned (v0.5), RFC-referencing, implementation-neutral
- **Severity**: Polish
- **Effort**: XS
- **Recommendation**: **Fix before submission** (one sentence in protocol.md)
- **Evidence**: `docs/protocol.md:1-14`
- **Why it matters**: Standards-track intent differentiates from throwaway projects

---

## Cross-Cutting Themes

1. **Input validation is the weakest security layer**: Unbounded `parameters` dict, unvalidated policy rules, broad character sets on `action`/`resource` fields enabling prompt injection, unbounded `/chain` response. Multiple S-effort fixes needed.

2. **Operational maturity is the weakest category overall**: Static health checks, no metrics, no tracing, no alerting, no backup docs. The system is built to demo, not to operate.

3. **Developer experience has high-impact low-effort fixes**: SDK extraction, one integration example, and a getting-started tutorial would dramatically improve first impressions.

4. **Competitive positioning is entirely missing**: Zero mentions of Auth0, Okta, Vanta, Drata, Aembit, or Anthropic anywhere in docs. This is all XS-effort writing.

5. **AI agent pipeline is well-designed but fragile**: Non-deterministic verdicts, no model fallback, no disagreement handling, and no quarantine reversal create a pipeline that works impressively in demos but has known failure modes in production.

6. **Multi-tenancy is structurally present but operationally locked**: Firestore data model supports tenants, but the API hardcodes one tenant. This is a documented architectural gap, not a missing concept.

---

## Prioritization Matrix

All gaps sorted by [Severity, Effort]. Highest severity / lowest effort first.

| # | Gap | Category | Severity | Effort | Recommendation |
|---|-----|----------|----------|--------|----------------|
| 1.9 | Dry-run bypasses auth + pollutes rate limits | Core Auth | Significant | XS | **Fix before submission** |
| 5.2 | No /.well-known/security.txt | Compliance | Significant | XS | **Fix before submission** |
| 9.1 | No Auth0/Okta positioning | Competitors | Significant | XS | **Fix before submission** |
| 9.2 | No Vanta/Drata positioning | Competitors | Significant | XS | **Fix before submission** |
| 9.3 | No Anthropic governance positioning | Competitors | Significant | XS | **Fix before submission** |
| 10.3 | No standards body statement | Trust | Polish | XS | **Fix before submission** |
| 6.2 | Policy binding delete no confirmation | UI Polish | Polish | XS | **Fix before submission** |
| 2.3 | No rate limit on registration challenges | Security | Significant | S | **Fix before submission** |
| 2.5 | MCP_AUTH_TOKEN in plain env vars | Security | Significant | S | **Fix before submission** |
| 2.6 | Unbounded input fields (parameters dict) | Security | Significant | S | **Fix before submission** |
| 2.7 | GET /chain unbounded response | Security | Significant | S | **Fix before submission** |
| 2.9 | Prompt injection on action/resource | Security | Significant | S | **Fix before submission** |
| 3.1 | Static health checks | Ops | Significant | S | **Fix before submission** |
| 4.2 | No LangChain/CrewAI examples | DevEx | Significant | S | **Fix before submission** |
| 4.3 | No getting-started tutorial | DevEx | Significant | S | **Fix before submission** |
| 5.4 | Compliance corpus missing NIST SP 800-53 | Compliance | Significant | S | **Fix before submission** |
| 8.1 | Investigator can't access agent provenance | AI Agents | Significant | S | **Fix before submission** |
| 9.4 | No build-vs-buy section | Competitors | Significant | S | **Fix before submission** |
| 10.1 | No open source strategy statement | Trust | Significant | S | **Fix before submission** |
| 6.1 | Silent error swallowing on list fetches | UI Polish | Polish | S | **Fix before submission** |
| 6.3 | No export capability (CSV/JSON) | UI Polish | Polish | S | **Fix before submission** |
| 4.1 | No SDK package | DevEx | Significant | M | **Fix before submission** |
| 3.6 | No docker-compose for local dev | Ops | Significant | M | **Fix before submission** |
| 1.5 | No delegation mechanism | Core Auth | Significant | L | Document as known limitation |
| 1.6 | No action context binding | Core Auth | Significant | S | Document as known limitation |
| 1.7 | Revocation propagation (60s window) | Core Auth | Significant | M | Document as known limitation |
| 2.1 | No automated key rotation | Security | Significant | M | Document as known limitation |
| 2.4 | In-memory JTI replay caches | Security | Significant | M | Document as known limitation |
| 3.5 | No backup/restore procedure | Ops | Significant | S | Document as known limitation |
| 5.1 | No SOC 2 / ISO 27001 mappings | Compliance | Significant | M | Document as known limitation |
| 5.3 | No penetration test report | Compliance | Significant | XL | Document as known limitation |
| 6.4 | No multi-user / account management | UI Polish | Significant | XL | Defer to v1.0 |
| 7.1 | No per-tenant quotas | Scale | Significant | M | Document as known limitation |
| 7.2 | Hardcoded single tenant | Scale | Significant | M | Document as known limitation |
| 7.3 | get_chain() loads all receipts | Scale | Significant | M | Document as known limitation |
| 8.2 | No quarantine reversal workflow | AI Agents | Significant | M | Document as known limitation |
| 8.3 | No AI agent disagreement handling | AI Agents | Significant | L | Document as known limitation |
| 8.4 | No model fallback | AI Agents | Significant | S | Document as known limitation |
| 10.2 | No independent security audit plan | Trust | Significant | XS | Document as known limitation |

---

## What's NOT in this audit

- Business model, pricing strategy, or go-to-market decisions
- Hiring plans or team structure recommendations
- Competitor financial analysis or market sizing
- Whether to pursue specific enterprise verticals

## What this audit does not do

This audit identifies gaps. It does not prioritize building any of them. The recommendation column suggests posture (fix vs document vs defer) but the decision to actually invest engineering time against any gap belongs to the founder.
