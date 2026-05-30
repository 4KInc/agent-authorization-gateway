"""The AI routing brain — an ADK LlmAgent powered by Gemini 2.5 Pro.

Given a natural-language description of what an agent needs to do,
identifies which A2A agent(s) in the directory are best positioned to help.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
from typing import Dict, List

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool
from google.cloud import firestore

from .directory import list_entries

logger = logging.getLogger(__name__)

ROUTING_INSTRUCTION = """\
You are the Discovery Coordinator's routing brain. When a user asks
"I need an agent that can do X," your job is to read the directory
of known A2A agents and identify which one(s) are best positioned
to help.

Procedure:
1. Call list_directory() to read all known agents.
2. Analyze each agent's skills (from its agent card) and
   ai_assessed_capabilities (the natural language summary).
3. Identify which agents match the request. Prefer specific
   matches over general ones. Prefer TRUSTED over REVIEW.
4. If multiple agents match, rank them.
5. If no agents match, say so explicitly. Do not fabricate
   a match.

Return JSON:
{
  "matches": [
    {
      "agent_card_url": "<url>",
      "agent_name": "<name from agent card>",
      "skill_invoked": "<which of the agent's skills applies>",
      "confidence": "HIGH" | "MEDIUM" | "LOW",
      "rationale": "<why this agent matches>"
    }
  ],
  "no_match_explanation": "<if no matches, why>"
}

Return ONLY the JSON object, no preamble, no markdown.
"""


def _make_adk_tools(db: firestore.Client):
    def list_directory() -> str:
        """List all known A2A agents in the discovery directory.
        Returns a JSON array of agent directory entries including
        agent_card_url, agent_card (with name, description, skills),
        ai_assessed_capabilities, trust_level, and health_status.
        """
        try:
            entries = list_entries(db)
        except Exception as e:
            logger.warning("Failed to list directory: %s", e)
            return json.dumps({"error": str(e)})
        summary = []
        for entry in entries:
            card = entry.get("agent_card", {})
            summary.append({
                "agent_card_url": entry.get("agent_card_url"),
                "name": card.get("name", "unknown"),
                "description": card.get("description", ""),
                "skills": entry.get("self_described_skills", []),
                "ai_assessed_capabilities": entry.get("ai_assessed_capabilities", ""),
                "trust_level": entry.get("trust_level", "REVIEW"),
                "health_status": entry.get("health_status", "unknown"),
            })
        return json.dumps(summary, default=str)

    return [FunctionTool(list_directory)]


def build_routing_agent(db: firestore.Client, model: str = "gemini-2.5-pro") -> LlmAgent:
    tools = _make_adk_tools(db)
    return LlmAgent(
        name="discovery_router",
        model=model,
        instruction=ROUTING_INSTRUCTION,
        tools=tools,
        description="Routes capability questions to matching A2A agents in the directory.",
    )


def run_routing(agent: LlmAgent, question: str) -> Dict:
    """Run the routing agent with a capability question and return parsed result."""
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    try:
        runner = InMemoryRunner(agent=agent, app_name="discovery-coordinator")
        user_id = "coordinator-system"

        async def _create_and_run():
            session = await runner.session_service.create_session(
                app_name="discovery-coordinator", user_id=user_id,
            )
            content = types.Content(
                role="user",
                parts=[types.Part.from_text(text=question)],
            )
            out = ""
            events = runner.run(
                user_id=user_id,
                session_id=session.id,
                new_message=content,
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

    except Exception:
        logger.exception("Routing agent invocation failed")
        return {"matches": [], "no_match_explanation": "Routing agent invocation failed."}

    cleaned = raw_output.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.startswith("json"):
            cleaned = cleaned[4:].strip()

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        logger.warning("Routing agent returned non-JSON: %s", cleaned[:500])
        return {"matches": [], "no_match_explanation": "Routing agent returned non-parseable output."}

    if not isinstance(parsed, dict):
        return {"matches": [], "no_match_explanation": "Unexpected output format."}

    return parsed


def assess_capabilities(card: Dict, model: str = "gemini-2.5-pro") -> str:
    """Use Gemini to produce a natural-language summary of an agent's capabilities."""
    from google import genai

    name = card.get("name", "Unknown Agent")
    description = card.get("description", "")
    skills = card.get("skills", [])
    skills_text = ""
    for s in skills:
        if isinstance(s, dict):
            sid = s.get("id") or s.get("name", "")
            sdesc = s.get("description", "")
            skills_text += f"  - {sid}: {sdesc}\n"
        else:
            skills_text += f"  - {s}\n"

    prompt = (
        f"Summarize in one paragraph what this A2A agent does, based on its agent card.\n\n"
        f"Name: {name}\n"
        f"Description: {description}\n"
        f"Skills:\n{skills_text}\n"
        f"Write a concise, natural-language summary (2-4 sentences) of this agent's "
        f"capabilities. Focus on what problems it solves and what actions it can perform."
    )

    try:
        client = genai.Client()
        response = client.models.generate_content(model=model, contents=prompt)
        return response.text.strip()
    except Exception as e:
        logger.warning("Gemini capability assessment failed: %s", e)
        return f"{name}: {description}"
