"""Orchestrator Agent - root agent that delegates between all six Gate agents.

  User
    |
  Orchestrator (root_agent)
    ├── Gateway Agent - security queries (stats, chain, keys, verify)
    ├── Worker Agent - data requests (authorize then execute)
    ├── Auditor Agent - compliance audit reports and citations
    ├── Recommender Agent - policy change proposals
    ├── Investigator Agent - incident reports from CONFLICT verdicts
    ├── Coordinator Agent - A2A agent directory and capability routing
    └── Isolator Agent - rogue agent quarantine records
"""

from google.adk.agents import Agent

from .agent import gateway_agent

# Import worker with path setup
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from worker.agent import worker_agent

from .tools.multi_agent_tools import (
    query_audit_reports, audit_receipt, get_auditor_keys,
    query_policy_proposals, get_recommender_keys,
    query_incidents, get_investigator_keys,
    route_capability, list_known_agents, get_coordinator_keys,
    query_isolation_records, get_isolator_keys,
)

# --- Sub-agents for each AI service ---

auditor_agent = Agent(
    model="gemini-2.5-flash",
    name="auditor",
    description="Compliance auditor. Queries audit reports with OWASP/NIST citations, triggers on-demand audits of receipts.",
    instruction="""You are the Policy Auditor agent. You analyze authorization receipts against compliance frameworks
(OWASP NHI Top 10, NIST AI RMF, NIST SP 800-53) using Gemini 2.5 Pro and Vertex AI Search for RAG.

You can:
- Query existing audit reports and their verdicts (ALIGNED, CONFLICT, INSUFFICIENT_EVIDENCE)
- Trigger on-demand audits of specific receipts
- Show the Auditor's Ed25519 public signing key

Each audit report is independently signed with the Auditor's own Ed25519 key.""",
    tools=[query_audit_reports, audit_receipt, get_auditor_keys],
)

recommender_agent = Agent(
    model="gemini-2.5-flash",
    name="recommender",
    description="Policy recommender. Queries policy change proposals generated from CONFLICT pattern detection.",
    instruction="""You are the Policy Recommender agent. You detect patterns across CONFLICT audit verdicts
and propose scope-tightening policy changes for human review.

You can:
- Query existing policy proposals with their confidence levels and motivating audit IDs
- Show the Recommender's Ed25519 public signing key

Every proposal is signed with the Recommender's own Ed25519 key and requires human_review_required=true.""",
    tools=[query_policy_proposals, get_recommender_keys],
)

investigator_agent = Agent(
    model="gemini-2.5-flash",
    name="investigator",
    description="Incident investigator. Queries incident reports assembled from CONFLICT-triggered evidence.",
    instruction="""You are the Incident Investigator agent. When CONFLICT audit verdicts surface,
you assemble evidence from receipts, agent registrations, and recent activity into signed incident reports.

You can:
- Query existing incident reports with severity, timeline, and recommended actions
- Show the Investigator's Ed25519 public signing key

Each incident report is signed with the Investigator's own Ed25519 key.""",
    tools=[query_incidents, get_investigator_keys],
)

coordinator_agent = Agent(
    model="gemini-2.5-flash",
    name="coordinator",
    description="A2A discovery coordinator. Routes capability questions to matching agents and maintains the agent directory.",
    instruction="""You are the Discovery Coordinator agent. You maintain an A2A directory of agents
and route natural-language capability questions to the best-matching agent.

You can:
- Route capability questions (e.g., "which agent handles compliance audits?")
- List all agents registered in the A2A directory
- Show the Coordinator's Ed25519 public signing key

Routing decisions are signed with the Coordinator's own Ed25519 key.""",
    tools=[route_capability, list_known_agents, get_coordinator_keys],
)

isolator_agent = Agent(
    model="gemini-2.5-flash",
    name="isolator",
    description="Rogue agent quarantine. Queries isolation records showing agents that were quarantined for policy violations.",
    instruction="""You are the Isolator agent. You quarantine agents exhibiting rogue behavior patterns -
repeated policy violations, suspicious authorization attempts, or HIGH/CRITICAL incident triggers.

You can:
- Query isolation records showing which agents were quarantined, why, and when
- Show the Isolator's Ed25519 public signing key

Every quarantine action is signed with the Isolator's own Ed25519 key. Quarantine is reversible by human review.""",
    tools=[query_isolation_records, get_isolator_keys],
)

# --- Orchestrator ---

ORCHESTRATOR_INSTRUCTION = """You are the Gate Orchestrator. You manage six specialized agents for AI agent authorization governance:

1. **Gateway Agent** ("authorization_gateway") - Security and audit inspection.
   Route here for: chain statistics, receipt chain, Merkle root, public signing key, receipt verification.

2. **Worker Agent** ("worker_analytics") - Data analytics with authorization enforcement.
   Route here for: reading, querying, or searching data. The Worker requests authorization from the Gateway before executing.

3. **Auditor Agent** ("auditor") - Compliance audit reports.
   Route here for: audit reports, compliance verdicts (ALIGNED/CONFLICT), OWASP/NIST citations, on-demand auditing of receipts.

4. **Recommender Agent** ("recommender") - Policy change proposals.
   Route here for: policy proposals, pattern detection across CONFLICT audits, scope-tightening recommendations.

5. **Investigator Agent** ("investigator") - Incident reports.
   Route here for: incident reports, CONFLICT-triggered investigations, severity assessments, recommended actions.

6. **Coordinator Agent** ("coordinator") - A2A agent directory.
   Route here for: which agent handles a capability, listing registered agents, A2A discovery.

7. **Isolator Agent** ("isolator") - Rogue agent quarantine.
   Route here for: isolation records, quarantined agents, containment actions.

ROUTING RULES:
- Data requests -> Worker Agent
- Security/chain/receipt/key queries -> Gateway Agent
- Compliance audit questions -> Auditor Agent
- Policy change proposals -> Recommender Agent
- Incident investigation -> Investigator Agent
- Agent discovery/routing -> Coordinator Agent
- Quarantine/isolation -> Isolator Agent
- If unclear, ask the user what they need

IMPORTANT: Transfer to the appropriate sub-agent. Do NOT call tools directly.

When greeting, briefly list all six agents and what each handles."""

orchestrator_agent = Agent(
    model="gemini-2.5-flash",
    name="orchestrator",
    description="Routes requests across six specialized Gate agents: Gateway, Worker, Auditor, Recommender, Investigator, Coordinator, and Isolator.",
    instruction=ORCHESTRATOR_INSTRUCTION,
    sub_agents=[
        gateway_agent,
        worker_agent,
        auditor_agent,
        recommender_agent,
        investigator_agent,
        coordinator_agent,
        isolator_agent,
    ],
)
