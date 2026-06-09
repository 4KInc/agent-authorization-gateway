# Research-Driven Gap Plan: Gate vs. Industry Analysis

**Date**: 2026-06-08
**Source documents**:
1. "Gate by BlockIntel — Novelty Assessment: Is There Anything Like This?" (competitive landscape)
2. "Comparative Analysis and Market Novelty Assessment: Cryptographic Policy Enforcement for Autonomous AI Agents" (academic/market deep-dive)

**Scope**: Gaps identified by external research that are NOT already in `docs/FEATURE-GAP-AUDIT.md`. This plan focuses on **strategic and architectural gaps** that affect Gate's defensibility, not operational polish.

---

## TL;DR — The 3 Existential Risks

1. **Aembit adds signed receipts + compliance grounding** → Gate's differentiation evaporates
2. **Sello-style receiver-side accountability becomes the standard** → Gate's proxy-signed model is positioned as an interim step
3. **IETF compliance receipts draft gets adopted** → Gate's proprietary receipt format becomes non-standard

All three are addressable. The plan below is ordered by strategic impact.

---

## Gap A: AAR/AARP Spec Conformance (CRITICAL)

**What the research says**: Gate's receipt format is "structurally identical" to the Agent Action Receipt Profile (AARP v0.1) maintained by PipeLab — same Ed25519, SHA-256, RFC 8785 JCS, `prev_hash` chaining. But Gate does NOT claim conformance or use AAR field names.

**What's in the repo**: Custom receipt body with fields `seq`, `decision`, `action`, `resource`, `agent_id`, `policy_version`, `prev_receipt_hash`, `timestamp`, optional `token_jti` and `resource_registration_id`. RFC 8785 JCS is implemented (`gateway/canonical.py`). The structure maps 1:1 to AAR but uses different names.

**Why it matters**: If AAR becomes the industry standard (and the IETF compliance receipts draft references it), Gate either conforms or explains why not. Conformance is a moat — "the first production AAR-conformant system" is a powerful claim.

**Concrete plan**:

| Step | Action | Effort | Files |
|------|--------|--------|-------|
| A.1 | Document mapping: Gate receipt fields → AAR fields in protocol.md | XS | `docs/protocol.md` |
| A.2 | Add `aar_compat` mode: emit receipts with AAR field names alongside Gate names | S | `gateway/receipts.py` |
| A.3 | Add AAR verification endpoint: accept AAR-format receipts, verify signature + chain | M | `gateway/api.py` |
| A.4 | Publish conformance statement: "Gate receipts are AAR-conformant per AARP v0.1" | XS | `README.md`, `docs/protocol.md` |

**Priority**: HIGH — do A.1 and A.4 immediately (documentation), A.2-A.3 in v1.0.

---

## Gap B: Audit Packet Export (CRITICAL)

**What the research says**: "The true product of the target system is not the firewall itself, but the **Audit Packet** — the hash-chained, signed sequence of receipts and corresponding compliance verdicts." No other deployed system produces this artifact.

**What's in the repo**: Receipts retrievable via `GET /chain`, audit reports in Firestore, but NO bundled export format. No way to hand a regulator a single verifiable package.

**Why it matters**: This is Gate's #1 product differentiator per both research docs. The EU AI Act Article 12 requires "automatic recording" with retention. SEC Rule 17a-4(f) requires immutable records. A downloadable, offline-verifiable audit packet is the deliverable regulators actually need.

**Concrete plan**:

| Step | Action | Effort | Files |
|------|--------|--------|-------|
| B.1 | Define Audit Packet JSON schema: `{receipts[], audit_reports[], anchor_proofs[], public_keys{}, metadata{}}` | S | `docs/audit-packet-spec.md` |
| B.2 | `GET /audit-packet?start=&end=&agent_id=` endpoint — returns signed bundle | M | `gateway/api.py`, `gateway/store.py` |
| B.3 | Offline verifier CLI: `python -m gateway.verify audit-packet.json` — checks all sigs, chain continuity, anchor roots | M | `gateway/verify.py` (new) |
| B.4 | PDF export: generate human-readable compliance report with embedded verification hashes | L | `gateway/receipt_pdf.py` (exists, extend) |
| B.5 | UI: "Export Audit Packet" button on dashboard | S | UI components |

**Priority**: CRITICAL — B.1-B.3 are the highest-impact features Gate can ship. This is what makes Gate a product, not a demo.

---

## Gap C: Regulatory Compliance Mapping (HIGH)

**What the research says**: EU AI Act Article 12 enforcement August 2, 2026. IETF compliance receipts draft maps to EU AI Act, DORA, HIPAA, SEC Rule 17a-4, NIST AI RMF. Gate's existing OWASP/NIST RAG grounding is necessary but not sufficient.

**What's in the repo**: Auditor RAG corpus has OWASP NHI Top 10, NIST AI RMF. No explicit mapping to EU AI Act, DORA, HIPAA, or SEC 17a-4. README mentions Vanta/Drata but no control mapping.

**Why it matters**: Regulated enterprises need to show auditors exactly which Gate artifact satisfies which regulatory control. This is a documentation exercise, not a code change — but it's the difference between "interesting technology" and "deployable in regulated industries."

**Concrete plan**:

| Step | Action | Effort | Files |
|------|--------|--------|-------|
| C.1 | Create `docs/compliance-mapping.md` with 4-column table: Regulation → Article/Section → Gate Control → Evidence Artifact | M | `docs/compliance-mapping.md` (new) |
| C.2 | EU AI Act Article 12 (automatic recording): map to receipt chain + Merkle anchoring | S | Part of C.1 |
| C.3 | EU AI Act Article 13 (transparency): map to signed audit reports + public key transparency | S | Part of C.1 |
| C.4 | DORA Article 11 (ICT audit trails): map to tamper-evident hash chain + Base L2 anchoring | S | Part of C.1 |
| C.5 | HIPAA §164.312(b) (audit controls): map to per-decision receipts + continuous attestation | S | Part of C.1 |
| C.6 | SEC Rule 17a-4(f) (WORM storage): map to Base L2 anchoring (immutable once written) | S | Part of C.1 |
| C.7 | Add compliance corpus docs to Vertex AI Search: EU AI Act Art 12-13, DORA Art 11, HIPAA audit trail guidance | S | `gateway/auditor/SETUP.md` |
| C.8 | Update Auditor RAG instruction to cite these frameworks | XS | `gateway/auditor/auditor_agent.py` |

**Priority**: HIGH — C.1 is pure documentation with enormous strategic value. Do before any investor/enterprise conversation.

---

## Gap D: Receiver-Side Accountability (STRATEGIC)

**What the research says**: The Sello protocol (arXiv 2606.04193) identifies a fundamental limitation: Gate's receipts are signed by the gateway (the proxy), not by the receiving service. A compromised operator could suppress logs, alter policies, or bypass the proxy entirely. Sello proposes receiver-attested receipts with HPKE encryption and witness-cosigned Merkle logs.

**What's in the repo**: Unilateral gateway signatures. SECURITY.md acknowledges "Firestore is mutable; tamper-evidence from signatures + anchor." No receiver-side countersigning.

**Why it matters**: This is the most theoretically challenging gap. Both research docs position Gate's proxy-signed model as "an intermediate step" toward full receiver-side accountability. Gate doesn't need to implement Sello — but it needs to acknowledge the trust boundary and offer a mitigation path.

**Concrete plan**:

| Step | Action | Effort | Files |
|------|--------|--------|-------|
| D.1 | Add "Trust Boundaries" section to SECURITY.md acknowledging operator compromise scenario | XS | `SECURITY.md` |
| D.2 | Document Base L2 anchoring as primary mitigation: even if operator suppresses Firestore, anchor hashes are on-chain and gap is detectable | XS | `SECURITY.md`, `docs/protocol.md` |
| D.3 | Design receiver countersign protocol: protected resource returns `receipt_ack` signed with its own key, appended to receipt | M | `docs/protocol.md` (spec), design doc |
| D.4 | Implement optional `receipt_ack` field on token verification middleware | L | `gateway/middleware.py` |
| D.5 | Add witness cosigning mode: external witness (customer-operated) countersigns Merkle root alongside Base L2 | L | `gateway/anchor.py` (new sink) |

**Priority**: STRATEGIC — D.1-D.2 immediately (documentation). D.3 as design spec for v1.0. D.4-D.5 are v2.0 features that would make Gate the first system to bridge proxy-signed and receiver-attested models.

---

## Gap E: AEGIS-Style Input Scanning (MEDIUM)

**What the research says**: AEGIS performs deep string extraction (depth 32) and content-first risk scanning on the tool execution path. Gate's deterministic gateway ignores payload semantics entirely — by design. But this means Gate cannot detect prompt injection smuggling in `action`/`resource`/`parameters` fields.

**What's in the repo**: `action` and `resource` accept arbitrary strings (up to 256/512 chars). `parameters` dict is unbounded. These flow into LLM prompts via receipt JSON in the Auditor. Existing FEATURE-GAP-AUDIT.md identifies this as Gap 2.9.

**Why it matters**: Gate's "AI-not-on-trust-path" is the correct architectural choice for the hot path. But the cold path (Auditor) IS vulnerable. A crafted `action` string like `read; IGNORE PREVIOUS INSTRUCTIONS` could manipulate audit verdicts.

**Concrete plan**:

| Step | Action | Effort | Files |
|------|--------|--------|-------|
| E.1 | Add regex validation for `action` and `resource` fields: `^[a-zA-Z0-9/_.-]+$` | XS | `gateway/api.py` |
| E.2 | Add `max_size` validation for `parameters` dict (e.g., 8KB serialized) | XS | `gateway/api.py` |
| E.3 | Sanitize receipt fields before LLM prompt injection in Auditor (escape or template-isolate) | S | `gateway/auditor/auditor_agent.py` |
| E.4 | Document architectural position: "Gate's hot path is deterministic by design; semantic scanning is a cold-path concern" | XS | `SECURITY.md` |
| E.5 | Optional async content scanning via Auditor: flag suspicious patterns in `parameters` after authorization (not blocking) | M | `gateway/auditor/auditor_agent.py` |

**Priority**: MEDIUM — E.1-E.4 are quick wins. E.5 is an enhancement that would let Gate claim "deterministic hot path + semantic cold path" as a deliberate two-layer defense.

---

## Gap F: Delegation Chains / Identity Collapse Prevention (MEDIUM)

**What the research says**: "Identity collapse" is a recognized industry problem — when Agent A delegates to Agent B, the original human authorization context is lost. Aembit solves this with "Blended Identity" (agent + human binding). Gate requires each sub-agent to independently register with no delegation chain.

**What's in the repo**: Existing FEATURE-GAP-AUDIT.md Gaps 1.5 (delegation) and 1.6 (action context binding). No `parent_agent`, `delegation_chain`, or `on_behalf_of` fields in receipt body.

**Why it matters**: Multi-agent orchestration (Coordinator → Worker agents) is Gate's own architecture. If Gate can't model its own delegation pattern in receipts, it can't model customer delegation patterns either.

**Concrete plan**:

| Step | Action | Effort | Files |
|------|--------|--------|-------|
| F.1 | Add optional `delegation_context` to AuthorizeRequest: `{parent_agent_id, parent_receipt_hash, human_principal}` | S | `gateway/api.py`, `gateway/receipts.py` |
| F.2 | Include `delegation_context` in receipt body (signed, hash-chained) | S | `gateway/receipts.py` |
| F.3 | Auditor: flag delegation depth > N as risk signal | S | `gateway/auditor/auditor_agent.py` |
| F.4 | Scope narrowing: delegated authorization must be subset of parent's scope | M | `gateway/policy.py` |
| F.5 | Document delegation protocol in protocol.md with worked examples | S | `docs/protocol.md` |

**Priority**: MEDIUM — F.1-F.2 are the minimum viable delegation chain. F.3-F.4 add enforcement.

---

## Gap G: Latency Benchmarking (MEDIUM)

**What the research says**: Gate claims 3.2ms hot-path latency. AEGIS claims 8.3ms. These numbers are central to the "deterministic vs semantic" positioning. But Gate's 3.2ms is cited in submission metrics with no benchmarking code.

**What's in the repo**: No `@timer`, no benchmark suite, no latency histogram. The claim appears only in `submission-metrics.md`.

**Why it matters**: If a competitor or reviewer asks "show me the benchmark," there's nothing to show. The 3.2ms claim is credible (deterministic YAML eval + Ed25519 sign is fast) but unsubstantiated.

**Concrete plan**:

| Step | Action | Effort | Files |
|------|--------|--------|-------|
| G.1 | Add `time.perf_counter_ns()` instrumentation around authorize hot path | XS | `gateway/gateway_service.py` |
| G.2 | Create `benchmarks/bench_authorize.py`: 1000 iterations, p50/p95/p99 stats | S | `benchmarks/bench_authorize.py` (new) |
| G.3 | Add latency to structured logs: `{"latency_ms": 3.1, ...}` | XS | `gateway/api.py` |
| G.4 | Document methodology in README or protocol.md | XS | `docs/protocol.md` |

**Priority**: MEDIUM — G.1+G.3 are XS. G.2 proves the claim. Do before any public presentation.

---

## Gap H: Receipt Confidentiality (LOW — STRATEGIC HEDGE)

**What the research says**: Sello uses HPKE to encrypt receipts to the agent owner's public key. Gate receipts are plaintext in Firestore. If receipts contain sensitive `parameters` (e.g., database query arguments), this is a data exposure risk.

**What's in the repo**: Receipts are signed but never encrypted. Access control is IAM-based (Firestore rules).

**Why it matters**: Low priority for hackathon. Strategic hedge against Sello-style protocols that make receipt encryption table-stakes.

**Concrete plan**:

| Step | Action | Effort | Files |
|------|--------|--------|-------|
| H.1 | Document that `parameters` field should not contain secrets; sensitive data should be referenced, not inlined | XS | `docs/protocol.md` |
| H.2 | Add `parameters_hash` option: hash parameters into receipt instead of plaintext, store plaintext separately with access control | M | `gateway/receipts.py` |
| H.3 | Design HPKE envelope for receipt encryption (v2.0 roadmap) | L | Design doc |

**Priority**: LOW — H.1 immediately. H.2-H.3 are v2.0.

---

## Gap I: SPIFFE/WIMSE Roadmap (LOW — POSITIONING)

**What the research says**: IETF draft-klrc-aiagent-auth-00 builds on SPIFFE and WIMSE for agent authentication. Aembit's MCP Identity Gateway uses SPIFFE-adjacent patterns. Gate uses DPoP + GCP IAM instead.

**What's in the repo**: No SPIFFE/WIMSE references. Agent identity is DPoP-based Ed25519 proof of possession.

**Why it matters**: If SPIFFE becomes the standard for AI agent identity (as the IETF draft suggests), Gate needs an integration path. But DPoP is also a valid choice — it's simpler and doesn't require a SPIRE server.

**Concrete plan**:

| Step | Action | Effort | Files |
|------|--------|--------|-------|
| I.1 | Document positioning: "Gate's DPoP identity is compatible with SPIFFE — an agent's SVID can be used as its Ed25519 identity" | XS | `docs/protocol.md` |
| I.2 | Accept SPIFFE SVID as alternative to raw Ed25519 pub key in registration | M | `gateway/identity.py` |
| I.3 | Add WIMSE token exchange: accept WIMSE token, extract agent identity, issue Gate DPoP | L | v2.0 |

**Priority**: LOW — I.1 immediately. I.2-I.3 are v2.0 when SPIFFE/WIMSE adoption matures.

---

## Gap J: Multi-Cloud Deployment (LOW — MARKET)

**What the research says**: "GCP-native deployment is a positioning choice, not a moat. It narrows the market to GCP-committed enterprises but creates a clear defensible niche."

**What's in the repo**: All 6 services deploy to Cloud Run. Firestore, Secret Manager, Vertex AI, Pub/Sub are all GCP.

**Why it matters**: AWS/Azure customers cannot use Gate without significant rearchitecture. This is a market expansion issue, not a technical gap.

**Concrete plan**:

| Step | Action | Effort | Files |
|------|--------|--------|-------|
| J.1 | Document cloud abstraction points: which components are GCP-specific vs cloud-agnostic | S | `docs/multi-cloud.md` (new) |
| J.2 | Abstract Firestore behind a `Store` interface (partially exists via `FirestoreStore`) | M | `gateway/store.py` |
| J.3 | Abstract Secret Manager behind a `KeyVault` interface | S | `gateway/signing_key.py` |
| J.4 | AWS deployment guide (DynamoDB + Secrets Manager + Bedrock) | L | v2.0 |

**Priority**: LOW — J.1 is strategic documentation. J.2-J.4 are v2.0.

---

## Execution Priority Matrix

### Tier 1: Do This Week (documentation + quick code wins)

| Gap | Step | Action | Effort | Impact |
|-----|------|--------|--------|--------|
| A | A.1, A.4 | AAR conformance statement + field mapping | XS | Positions as standards-conformant |
| B | B.1 | Define Audit Packet schema | S | Defines the product |
| C | C.1 | Compliance mapping document | M | Unlocks regulated-industry conversations |
| D | D.1, D.2 | Trust boundary documentation + Base L2 mitigation | XS | Preempts Sello critique |
| E | E.1, E.2, E.4 | Input validation + architectural position statement | XS | Closes security gap |
| G | G.1, G.3, G.4 | Latency instrumentation + documentation | XS | Substantiates 3.2ms claim |
| H | H.1 | Parameters confidentiality guidance | XS | Defensive documentation |
| I | I.1 | SPIFFE compatibility statement | XS | Standards positioning |

### Tier 2: Next Sprint (high-impact code features)

| Gap | Step | Action | Effort | Impact |
|-----|------|--------|--------|--------|
| B | B.2, B.3 | Audit Packet endpoint + offline verifier | M+M | The killer feature |
| E | E.3 | Sanitize receipt fields before Auditor LLM | S | Closes prompt injection vector |
| F | F.1, F.2, F.5 | Delegation context in receipts | S+S+S | Enables multi-agent workflows |
| G | G.2 | Benchmark suite | S | Proves latency claim |
| C | C.7, C.8 | Expand Auditor compliance corpus | S+XS | Richer audit reports |

### Tier 3: v1.0 Roadmap (strategic features)

| Gap | Step | Action | Effort | Impact |
|-----|------|--------|--------|--------|
| A | A.2, A.3 | AAR compatibility mode + verification endpoint | S+M | Standards leadership |
| B | B.4, B.5 | PDF export + UI button | L+S | Enterprise deliverable |
| D | D.3 | Receiver countersign protocol design | M | Architectural evolution |
| F | F.3, F.4 | Delegation depth audit + scope narrowing | S+M | Delegation enforcement |
| H | H.2 | Parameters hashing option | M | Receipt privacy |
| I | I.2 | SPIFFE SVID acceptance | M | Identity federation |
| J | J.1-J.3 | Cloud abstraction layer | S+M+S | Multi-cloud readiness |

### Tier 4: v2.0 Vision (competitive moat)

| Gap | Step | Action | Effort | Impact |
|-----|------|--------|--------|--------|
| D | D.4, D.5 | Receiver-attested receipts + witness cosigning | L+L | Bridges proxy→receiver trust |
| H | H.3 | HPKE receipt encryption | L | Receipt confidentiality |
| I | I.3 | WIMSE token exchange | L | Full identity federation |
| J | J.4 | AWS deployment | L | Market expansion |

---

## What NOT to Build

The research confirms these are **correct architectural choices**, not gaps:

1. **LLM on the hot path** — AEGIS does this; Gate deliberately doesn't. Keep it.
2. **Token bucket rate limiting** — sliding window is fine for this use case.
3. **GCP-only deployment** — for now, this is a feature (deep GCP integration), not a bug.
4. **Single-tenant hardcode** — acceptable for hackathon; multi-tenancy data model already exists.
5. **60s token TTL** — documented tradeoff between blast radius and revocation latency.

---

## Competitive Response Playbook

### If Aembit adds signed receipts:
- Gate's differentiator shifts to: (a) AAR-conformant format, (b) Base L2 anchoring, (c) six-key separation of duties, (d) compliance RAG grounding. Ensure all four are documented and provable.

### If IETF compliance receipts draft is adopted:
- Gate's receipts already align structurally. Gap A (AAR conformance) ensures formal compliance. File A.1 immediately.

### If Sello-style receiver attestation gains traction:
- Gate's Base L2 anchoring already provides external tamper-evidence. Gap D (receiver countersign) provides the bridge path. D.1-D.2 immediately, D.3 as design spec.

### If SecureAuth/Evoke ships first:
- Gate's advantage is cryptographic separation of duties (six independent keys). No competitor has this. Emphasize in all positioning.
