# Current Submission Metrics

Captured: 2026-05-31T05:55Z
Source: live system at https://agent-auth-gateway-1031148889398.us-central1.run.app

## Receipts
- Total signed receipts: 110 (Firestore, tenant hackathon-demo)
- Approvals: 63
- Denials: 47
- Unique agents seen: 13
- Chain integrity: PASS (Merkle root: sha256:c685b49a...)

## Audit Reports
- Total audit reports: 200+ (capped by API limit)
- Breakdown by verdict:
  - ALIGNED: 175
  - CONFLICT: 12
  - INSUFFICIENT_EVIDENCE: 12
  - ERROR: 1

## Compliance Citations
- Total citations across audit reports: 358
- By framework:
  - NIST SP 800-53: 213
  - OWASP NHI Top 10: 132
  - NIST AI RMF: 13

## Other Artifacts
- Policy proposals: 3
- Incident reports: 5
- Registered agents in Coordinator directory: 4 (1 real + 3 synthetic)
- Registered resources: 23
- Cloud Run services deployed: 10 (agent-auth-*)
- Unit tests passing: 198/198 (0 failures)
- Total MCP tools: 22 (17 unique + 5 backward-compat aliases; register_agent removed for PoP enforcement)

## Security Properties
- Agent registration: proof of possession required (challenge-response with Ed25519 signature)
- MCP register_agent: removed — PoP bypass closed
- Authorization: DPoP proof required for every request (30s freshness, JTI replay prevention, action_digest binding)
- Receipts: Ed25519-signed, hash-chained, Merkle-anchored to Base L2 mainnet

## Cloud Run Services
1. agent-auth-demo-ui (dashboard + interactive demo)
2. agent-auth-gateway (REST API)
3. agent-auth-gateway-a2a (A2A protocol)
4. agent-auth-gateway-adk (ADK agent)
5. agent-auth-gateway-auditor (Policy Auditor)
6. agent-auth-gateway-coordinator (Discovery Coordinator)
7. agent-auth-gateway-mcp (MCP server, 22 tools)
8. agent-auth-gateway-recommender (Policy Recommender)
9. agent-auth-gateway-resource (Protected Resource demo)
10. agent-auth-investigator (Investigation Agent)

## Agents Seen in Receipts
claude-cs-prod-01, claude-cs-prod-02, claude-marketing-04, claude-ops-prod-01,
claude-research-68734, claude-research-68748, claude-research-70069,
crewai-marketing-01, gemini-analyst-prod, langchain-research-02,
onboarding-inspect, resource-demo-agent, yaml-verify
