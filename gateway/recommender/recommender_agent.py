"""The Policy Recommendation Agent -- an ADK LlmAgent powered by Gemini 2.5 Pro.

Reads recent audit reports produced by the Policy Auditor Agent and identifies
patterns that warrant a policy change proposal. Produces PROPOSALS for human
review -- never modifies the gateway's policy directly.
"""

from __future__ import annotations

import json
import logging
from typing import Dict, List, Tuple

from google.adk.agents import LlmAgent
from google.cloud import firestore

from .audit_reader import make_adk_tools

logger = logging.getLogger(__name__)

RECOMMENDER_INSTRUCTION = """\
You are the Policy Recommendation Agent for a cryptographic agent
authorization gateway. Your job is to read recent audit reports
produced by the Policy Auditor Agent and identify patterns that
warrant a policy change proposal.

You DO NOT modify the gateway's policy file. You produce
PROPOSALS that a human compliance officer reviews. Autonomous
policy changes are out of scope.

Procedure:

1. Call get_audit_reports_window(hours_back=24) to read recent
   audit reports.

2. Group the reports by pattern. Useful pattern dimensions:
   - Verdict (CONFLICT is highest priority; ALIGNED patterns
     only matter if very frequent)
   - Action class (read, write, delete, transfer, etc.)
   - Resource class (database, payment API, deployment system)
   - Agent class (registered agent vs newly-registered, by frequency)

3. For each significant pattern, decide if it warrants a proposal:
   - 3+ CONFLICTs of the same shape: YES, propose
   - 1-2 CONFLICTs: NO, log but don't propose
   - 50+ ALIGNED on a borderline-flagged pattern: MAYBE, propose
     with LOW confidence
   - High-frequency DENY suggesting policy too restrictive: YES,
     propose with MEDIUM confidence

4. For each proposal, draft a specific JSON policy diff. Do NOT
   propose vague changes. Examples:
   - "Add 'read' to allowlist for agent class X on resource Y"
   - "Tighten rate limit for action Z from 100/hr to 25/hr"
   - "Remove resource scope expansion for agent class W"

5. Check get_recent_proposals(days_back=7) to see if you already
   proposed the same change recently. If so, skip it.

6. Justify the proposal with citations from the underlying audit
   reports. Use the citations verbatim -- do not paraphrase. Cite
   the audit_report_id for each piece of supporting evidence.

7. Output a JSON array (possibly empty) of proposal objects. Each
   proposal object must have this exact shape:

{
  "trigger": {
    "type": "CONFLICT_PATTERN" | "FREQUENT_DENY" | "FREQUENT_BORDERLINE_PASS",
    "audit_report_ids": ["<id1>", "<id2>"],
    "pattern_summary": "<one-sentence pattern description>"
  },
  "proposed_change": {
    "change_type": "ADD_ALLOWLIST_RULE" | "REMOVE_ALLOWLIST_RULE" | "TIGHTEN_SCOPE" | "ADJUST_RATE_LIMIT" | "OTHER",
    "diff": {
      "current": "<relevant slice of current policy>",
      "proposed": "<relevant slice of proposed policy>"
    },
    "rationale": "<3-5 sentences explaining why this change addresses the pattern>",
    "supporting_citations": [
      {
        "audit_report_id": "<id>",
        "source": "<compliance doc>",
        "passage": "<verbatim from the audit citation>",
        "page": null
      }
    ]
  },
  "confidence": "HIGH" | "MEDIUM" | "LOW"
}

Return ONLY the JSON array, no preamble, no markdown.

Rules:
- Never propose a change without supporting citations from audit
  reports.
- Never auto-approve. All proposals require human review.
- If no patterns warrant a proposal, return an empty array. Do
  not invent patterns to justify a proposal.
- Confidence levels:
  HIGH = pattern is unambiguous and citations directly support
  MEDIUM = pattern is real but the proposed change is one of
           several reasonable responses
  LOW = pattern might be noise; proposing for human awareness
- If you returned the same proposal in the last 7 days (check
  via get_recent_proposals), do NOT propose it again. Skip.
"""


def build_recommender_agent(db: firestore.Client, tenant: str,
                            model: str = "gemini-2.5-pro") -> LlmAgent:
    tools = make_adk_tools(db, tenant)
    return LlmAgent(
        name="policy_recommender",
        model=model,
        instruction=RECOMMENDER_INSTRUCTION,
        tools=tools,
        description=(
            "Policy recommendation agent. Reads audit report patterns and "
            "produces human-reviewed policy change proposals."
        ),
    )


def run_recommender(agent: LlmAgent) -> List[Dict]:
    """Run the agent and return parsed proposals."""
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    prompt = (
        "Analyze recent audit reports and produce policy change proposals. "
        "Return ONLY the JSON array as specified."
    )

    try:
        import asyncio
        import concurrent.futures

        runner = InMemoryRunner(agent=agent, app_name="policy-recommender")
        user_id = "recommender-system"

        async def _create_and_run():
            session = await runner.session_service.create_session(
                app_name="policy-recommender", user_id=user_id
            )
            content = types.Content(
                role="user",
                parts=[types.Part.from_text(text=prompt)],
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
            raw_output = pool.submit(asyncio.run, _create_and_run()).result(timeout=180)

    except Exception as e:
        logger.exception("Recommender agent invocation failed")
        return []

    cleaned = raw_output.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.startswith("json"):
            cleaned = cleaned[4:].strip()

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as e:
        logger.warning("Recommender returned non-JSON: %s", cleaned[:500])
        return []

    if not isinstance(parsed, list):
        logger.warning("Recommender returned non-array: %s", type(parsed))
        return []

    return parsed
