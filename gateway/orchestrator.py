"""Orchestrator Agent — root agent that delegates between Gateway and Worker.

This is the multi-agent architecture entry point:

  User
    ↓
  Orchestrator (root_agent)
    ├── Worker Agent — handles data requests (authorize → execute)
    └── Gateway Agent — handles security queries (stats, chain, keys, verify)

The orchestrator routes user requests to the appropriate sub-agent:
- Data requests → Worker (which internally calls authorize_action before executing)
- Security/audit requests → Gateway (chain stats, receipt verification, public keys)
"""

from google.adk.agents import Agent

from .agent import gateway_agent

# Import worker with path setup
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from worker.agent import worker_agent

ORCHESTRATOR_INSTRUCTION = """You are the Agent Authorization Gateway Orchestrator. You manage two specialized agents:

1. **Worker Agent** ("worker_analytics") — A data analytics agent that queries databases and APIs.
   Route to this agent when the user wants to:
   - Read, query, or search data
   - List datasets or tables
   - Analyze metrics or run reports
   - Any data access operation
   The Worker will automatically request authorization from the Gateway before executing.

2. **Gateway Agent** ("authorization_gateway") — The security and audit agent.
   Route to this agent when the user wants to:
   - Check chain statistics or Merkle root
   - View the receipt chain or verify receipts
   - Get the signing public key
   - Understand the security policy
   - Directly authorize or deny an action
   - Audit or verify past decisions

ROUTING RULES:
- If the user asks for data → transfer to Worker Agent
- If the user asks about security, audit, receipts, or authorization → transfer to Gateway Agent
- If unclear, ask the user what they need

IMPORTANT: You are the orchestrator. Do NOT call tools directly. Transfer to the appropriate sub-agent and let them handle the request.

When greeting the user, briefly introduce both agents and what they can do."""

orchestrator_agent = Agent(
    model="gemini-2.5-flash",
    name="orchestrator",
    description="Routes requests between the Worker Agent (data operations) and Gateway Agent (security/audit).",
    instruction=ORCHESTRATOR_INSTRUCTION,
    sub_agents=[worker_agent, gateway_agent],
)
