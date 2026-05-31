"""The Isolator Agent — an ADK LlmAgent powered by Gemini 2.5 Pro.

Triggered by HIGH/CRITICAL incident reports from the Investigator.
Analyzes the incident, identifies the rogue agent, and recommends
containment actions. The Isolator then executes containment by
revoking the agent's registration and logging the isolation record.

The Isolator is the ONLY agent that takes automated enforcement actions.
All other agents (Auditor, Recommender, Investigator) produce reports
for humans. The Isolator acts — but only when severity is HIGH or CRITICAL,
and every action is logged in a signed isolation record.
"""

from __future__ import annotations

import json
import logging
from typing import Dict, Optional

from google.adk.agents import LlmAgent

logger = logging.getLogger(__name__)

ISOLATOR_INSTRUCTION = """\
You are the Isolator Agent for a cryptographic agent authorization gateway.
When a security incident with HIGH or CRITICAL severity is detected, your
job is to analyze the incident report and determine containment actions.

Procedure:

1. Read the incident report. Identify the agent(s) involved, the severity,
   and the root cause hypothesis.

2. For each agent identified as an "actor" with role in a HIGH/CRITICAL
   incident, determine the appropriate containment action:
   - REVOKE_REGISTRATION: Remove the agent's public key from the registry.
     This prevents all future authorization requests from this agent.
   - RATE_LIMIT_ZERO: Recommend setting the agent's rate limit to zero
     (manual policy change needed — the Isolator cannot modify policy).
   - MONITOR_ONLY: The incident is serious but the agent may be legitimate.
     Flag for human review without revoking.

3. For each containment action, provide:
   - The agent_id to act on
   - The action type (REVOKE_REGISTRATION, RATE_LIMIT_ZERO, MONITOR_ONLY)
   - A rationale explaining why this action is appropriate
   - The evidence_id supporting the decision

4. Output a JSON object with this shape:

{
  "severity": "HIGH" | "CRITICAL",
  "agent_id": "<primary rogue agent>",
  "containment_actions": [
    {
      "agent_id": "<agent to contain>",
      "action": "REVOKE_REGISTRATION" | "RATE_LIMIT_ZERO" | "MONITOR_ONLY",
      "rationale": "<why this action>",
      "evidence_id": "<incident_id or audit_id>"
    }
  ],
  "summary": "<1-2 sentence summary of what happened and what was done>"
}

Rules:
- Only recommend REVOKE_REGISTRATION for agents that are clearly rogue
  (unauthorized actions, forged proofs, repeated policy violations).
- MONITOR_ONLY is the default for ambiguous cases.
- Every containment action MUST reference a specific evidence_id.
- Output ONLY the JSON. No preamble, no markdown.
"""


def build_isolator_agent(model: str = "gemini-2.5-pro") -> LlmAgent:
    return LlmAgent(
        name="agent_isolator",
        model=model,
        instruction=ISOLATOR_INSTRUCTION,
        tools=[],
        description=(
            "Security isolator agent. Analyzes HIGH/CRITICAL incidents and "
            "determines containment actions for rogue agents."
        ),
    )


def run_isolation_analysis(agent: LlmAgent, incident: Dict) -> Optional[Dict]:
    """Run the agent on an incident report. Returns parsed containment plan."""
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    prompt = (
        f"Analyze this incident report and determine containment actions.\n\n"
        f"Incident:\n{json.dumps(incident, default=str, indent=2)}"
    )

    try:
        import asyncio
        import concurrent.futures

        runner = InMemoryRunner(agent=agent, app_name="agent-isolator")
        user_id = "isolator-system"

        async def _create_and_run():
            session = await runner.session_service.create_session(
                app_name="agent-isolator", user_id=user_id
            )
            content = types.Content(
                role="user",
                parts=[types.Part.from_text(text=prompt)],
            )
            out = ""
            events = runner.run(
                user_id=user_id, session_id=session.id, new_message=content,
            )
            if hasattr(events, "__aiter__"):
                async for event in events:
                    if event.content and event.content.parts:
                        for part in event.content.parts:
                            if hasattr(part, "text") and part.text:
                                out += part.text
            else:
                for event in events:
                    if event.content and event.content.parts:
                        for part in event.content.parts:
                            if hasattr(part, "text") and part.text:
                                out += part.text
            return out

        with concurrent.futures.ThreadPoolExecutor() as pool:
            raw_output = pool.submit(asyncio.run, _create_and_run()).result(timeout=120)

    except Exception as e:
        logger.exception("Isolator agent invocation failed")
        return None

    cleaned = raw_output.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.startswith("json"):
            cleaned = cleaned[4:].strip()

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        logger.warning("Isolator returned non-JSON: %s", cleaned[:500])
        return None

    return parsed
