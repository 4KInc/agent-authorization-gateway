"""A2A Server for the Isolator Agent."""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def create_agent_card():
    """Build the Isolator's A2A agent card."""
    from a2a.types import AgentCard, AgentSkill, AgentCapabilities, AgentProvider, AgentInterface

    url = os.environ.get("A2A_BASE_URL", "http://localhost:8080")

    card = AgentCard(
        name="Isolator Agent",
        description=(
            "Automated containment agent for rogue AI agents. Triggered by HIGH/CRITICAL "
            "incident reports from the Investigator. Analyzes incidents using Gemini 2.5 Pro, "
            "identifies rogue agents, revokes their registrations, and produces signed "
            "isolation records. The only Gate agent authorized to take enforcement actions."
        ),
        supported_interfaces=[
            AgentInterface(url=url, protocol_version="1.0"),
        ],
        version="0.1.0",
        capabilities=AgentCapabilities(streaming=False),
        default_input_modes=["text"],
        default_output_modes=["text"],
        skills=[
            AgentSkill(
                id="isolate_agent",
                name="Isolate Rogue Agent",
                description=(
                    "Analyze an incident report and execute containment actions. "
                    "Requires severity HIGH or CRITICAL. Produces a signed isolation record."
                ),
                tags=["isolation", "containment", "security", "enforcement"],
                examples=[
                    '{"skill":"isolate_agent","input":{"tenant":"hackathon-demo","trigger":{"incident_id":"inc-abc123"}}}'
                ],
            ),
            AgentSkill(
                id="query_isolation_records",
                name="Query Isolation Records",
                description=(
                    "List isolation records for a tenant. Each record documents "
                    "a containment action with the agent_id, severity, actions taken, "
                    "and evidence references."
                ),
                tags=["isolation", "query", "audit"],
                examples=[
                    '{"skill":"query_isolation_records","input":{"tenant":"hackathon-demo","limit":20}}'
                ],
            ),
            AgentSkill(
                id="explain_isolation",
                name="Explain Isolation",
                description=(
                    "Retrieve a specific isolation record by ID with full containment "
                    "actions, rationale, and evidence references."
                ),
                tags=["isolation", "explain"],
                examples=[
                    '{"skill":"explain_isolation","input":{"tenant":"hackathon-demo","isolation_id":"iso-abc123"}}'
                ],
            ),
        ],
        provider=AgentProvider(
            organization="4K Inc (BlockIntel)",
            url="https://github.com/4KInc/agent-authorization-gateway",
        ),
    )
    return card
