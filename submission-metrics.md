# Current Submission Metrics

Captured: 2026-06-04T02:00Z
Source: live system at https://agent-auth-gateway-1031148889398.us-central1.run.app

## Receipts
- Signed receipts on current chain: grows with each pipeline run (chain resets on redeploy; run the pipeline simulator to generate live receipts)
- Chain integrity: PASS (contiguous hash-linked, verify-chain returns PASS/PASS/[])

## Audit Reports
- Total audit reports: 200+ (capped by API limit)
- Breakdown by verdict:
  - ALIGNED: 175
  - CONFLICT: 12
  - INSUFFICIENT_EVIDENCE: 12
  - ERROR: 1

## Compliance Citations
- Total citations across audit reports: 519+
- By framework:
  - NIST SP 800-53: primary
  - OWASP NHI Top 10: primary
  - NIST AI RMF: supporting

## Other Artifacts
- Policy proposals: 3+
- Incident reports: 5+
- Registered agents in Coordinator directory: 4 (1 real + 3 synthetic)
- Registered resources: 23
- Cloud Run services deployed: 11+ (agent-auth-* plus demo-agent)
- Unit tests passing: 309/309 (0 failures)
- Total MCP tools: 30 (25 unique + 5 backward-compat aliases; register_agent removed for PoP enforcement)
- REST API endpoints: 38
- Python source files: 78
- Lines of Python code: 13,000+

## Agent Registry
- Active customer agent registrations: on-demand via UI or CLI
- Persistent: Firestore at tenants/{tenant}/agent_registry/{agent_id} (survives cold starts)
- System agents (Gateway, Auditor, Recommender, Investigator, Coordinator, Isolator): deployment-managed identity via Secret Manager with service-specific kid prefixes
- PoP enforcement: all REST registrations require proof of possession (challenge-response)
- Continuous attestation: 5-state liveness (LIVE, WARNING, STALE, SUSPENDED, UNKNOWN)

## Security Properties
- Customer agent registration: proof of possession required (challenge-response with Ed25519 signature)
- System agent identity: deployment-managed via Secret Manager (service-specific kid prefixes)
- MCP register_agent: removed (PoP bypass closed)
- Authorization: DPoP proof required for every request (30s freshness, JTI replay prevention, action_digest binding)
- Receipts: Ed25519-signed, hash-chained, Merkle-anchored to Base L2 mainnet
- Hot path: 3.2ms decision latency, async Firestore via evidence buffer
- Inter-service trust: Cloud Run IAM with per-service service accounts and OIDC tokens
- Production lockdown checklist: documented in DEPLOYMENT.md

## A2A Coverage
- All 6 agents publish A2A agent cards at /.well-known/agent-card.json
- Gateway: 4 skills (authorize_action, verify_receipt, get_public_key, get_chain_summary)
- Auditor: 3 skills (query_audits, audit_receipt, explain_verdict)
- Recommender: 3 skills (query_proposals, explain_proposal, analyze_patterns)
- Investigator: 3 skills (query_incidents, investigate_conflict, explain_incident)
- Coordinator: 3 skills (route_capability, list_known_agents, register_known_agent)
- Isolator: 3 skills (isolate_agent, query_isolation_records, explain_isolation)

## Cloud Run Services
1. agent-auth-demo-ui (dashboard + interactive demo)
2. agent-auth-gateway (REST API)
3. agent-auth-gateway-a2a (A2A protocol)
4. agent-auth-gateway-adk (ADK agent)
5. agent-auth-gateway-auditor (Policy Auditor)
6. agent-auth-gateway-coordinator (Discovery Coordinator)
7. agent-auth-gateway-mcp (MCP server, 30 tools)
8. agent-auth-gateway-recommender (Policy Recommender)
9. agent-auth-gateway-resource (Protected Resource demo)
10. agent-auth-investigator (Investigation Agent)
11. agent-auth-isolator (Isolator Agent)

## Google Cloud Services Used
- Cloud Run (11 services, scale-to-zero)
- Cloud Firestore (receipts, audit reports, proposals, incidents, registries, agent liveness)
- Vertex AI Model Garden (Gemini 2.5 Pro for 5 AI agents + Gemini 2.5 Flash for explain endpoints)
- Vertex AI Search (RAG compliance corpus: OWASP NHI Top 10, NIST AI RMF, NIST SP 800-53)
- Google genai SDK (Gemini-powered policy explanation + receipt narration)
- Google ADK (LlmAgent + FunctionTool for all 5 AI agents)
- A2A SDK (agent cards + skill dispatch on all 6 agents)
- Secret Manager (6 independent Ed25519 signing keys + 5 agent configs)
- Pub/Sub (Auditor -> Investigator CONFLICT pipeline)
- Cloud Scheduler (audit tick 5min, recommend tick 1hr)
- Cloud Build + Artifact Registry (container images)
- Cloud IAM (per-service access control with OIDC inter-service auth)
- Cloud Logging (structured JSON logs via google-cloud-logging client)
- Base L2 Mainnet (optional on-chain Merkle anchoring)
