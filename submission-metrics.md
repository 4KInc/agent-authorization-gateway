# Current Submission Metrics

Captured: 2026-05-31
Source: live system at https://agent-auth-gateway-1031148889398.us-central1.run.app

## Receipts
- Total signed receipts: 106 (seq 18-123)
- Approvals: 61
- Denials: 45
- Unique agents seen: 13
- Chain integrity: PASS (individual receipts); partial chain starts at seq 18

## Audit Reports
- Total audit reports: 345
- Breakdown by verdict:
  - ALIGNED: 246+
  - CONFLICT: 12+
  - INSUFFICIENT_EVIDENCE: 13+
  - ERROR: 2+
- Latest audit report timestamp: 2026-05-29T21:43:54.530249+00:00

## Compliance Citations
- Total citations across audit reports: 519+
- By framework:
  - NIST SP 800-53: 314+
  - OWASP NHI Top 10: 191+
  - NIST AI RMF: 14+

## Other Artifacts
- Policy proposals: 1
- Incident reports: 4
- Registered agents in Coordinator directory: 4 (1 real + 3 synthetic)
- Registered resources: 23 (migrated from receipt chain)
- Cloud Run services deployed: 10 (agent-auth-*)
- Unit tests passing: 198
- Total MCP tools: 22

## Cloud Run Services
1. agent-auth-demo-ui (dashboard)
2. agent-auth-gateway (REST API)
3. agent-auth-gateway-a2a (A2A protocol)
4. agent-auth-gateway-adk (ADK agent)
5. agent-auth-gateway-auditor (Policy Auditor)
6. agent-auth-gateway-coordinator (Discovery Coordinator)
7. agent-auth-gateway-mcp (MCP server)
8. agent-auth-gateway-recommender (Policy Recommender)
9. agent-auth-gateway-resource (Protected Resource demo)
10. agent-auth-investigator (Investigation Agent)

## Agents Seen in Receipts
claude-cs-prod-01, claude-cs-prod-02, claude-marketing-04, claude-ops-prod-01,
claude-research-68734, claude-research-68748, claude-research-70069,
crewai-marketing-01, gemini-analyst-prod, langchain-research-02,
onboarding-inspect, resource-demo-agent, yaml-verify
