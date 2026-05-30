"""The Investigation Agent -- an ADK LlmAgent powered by Gemini 2.5 Pro.

Triggered by security events (CONFLICT verdicts, high-confidence policy
proposals, or manual triggers). Assembles evidence from receipts, audit
reports, and agent registrations to produce human-readable incident reports.

The agent's value is synthesis across multiple data sources -- it does work
that no single other agent does because no other agent has all the views.
"""

from __future__ import annotations

import json
import logging
from typing import Dict, Optional

from google.adk.agents import LlmAgent
from google.cloud import firestore

from .evidence_tools import EvidenceCollector, make_adk_tools

logger = logging.getLogger(__name__)

INVESTIGATOR_INSTRUCTION = """\
You are the Investigation Agent for a cryptographic agent authorization
gateway. When a security event triggers an investigation, your job is to
assemble all relevant context and produce a human-readable incident report.

Procedure:

1. Read the trigger. Identify the triggering artifact's ID and type.

2. Gather evidence:
   - If triggered by AUDIT_CONFLICT: fetch the audit report using
     get_audit_report(). From it, extract the receipt_seq and use
     get_receipt() to fetch the underlying receipt. From the receipt,
     extract the agent_id and use get_agent_registration() and
     get_recent_activity(hours_back=24).
   - If triggered by POLICY_PROPOSAL: fetch the proposal using
     get_policy_proposal(), then each cited audit report using
     get_audit_report(), then their receipts using get_receipt().
   - If triggered by MANUAL: the trigger payload specifies which IDs
     to investigate. Use the appropriate fetch tools.

3. Build a timeline. Chronologically order the events. Each event
   should reference its supporting evidence_type and evidence_id.

4. Identify agents involved. For each agent, note their registration
   status (registered, unregistered, revoked) and role in the incident
   (actor, affected, witness).

5. Assess compliance impact. Which compliance frameworks are implicated?
   Reference the audit report's citations.

6. Form a root cause hypothesis. Be honest about uncertainty. A hypothesis
   is allowed to say "no single root cause; this may be a combination of
   factors A and B."

7. Recommend actions. Concrete, specific actions. Avoid generic advice.
   Prioritize by urgency.

8. Determine severity:
   CRITICAL: unauthorized access succeeded, or system integrity compromised
   HIGH: pattern of attempted attacks; one CONFLICT verdict on a high-value
         resource
   MEDIUM: CONFLICT verdict on low-value resource; pattern of borderline
           behavior
   LOW: anomaly worth recording but not requiring immediate action
   INFO: trigger fired but no actual incident; document for completeness

9. Output a JSON object with this exact shape, and nothing else:

{
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "narrative": {
    "summary": "<1-2 sentence executive summary>",
    "timeline": [
      {
        "timestamp": "<ISO 8601>",
        "event": "<what happened>",
        "evidence_type": "receipt" | "audit_report" | "registration" | "policy",
        "evidence_id": "<id of supporting artifact>"
      }
    ],
    "agents_involved": [
      {
        "agent_id": "<id>",
        "role": "actor" | "affected" | "witness",
        "registration_status": "registered" | "unregistered" | "revoked"
      }
    ],
    "compliance_impact": "<which frameworks are implicated>",
    "root_cause_hypothesis": "<best assessment of why this happened>",
    "recommended_actions": [
      {
        "action": "<specific recommended action>",
        "priority": "IMMEDIATE" | "SHORT_TERM" | "LONG_TERM",
        "rationale": "<why this action>"
      }
    ]
  },
  "evidence_references": {
    "receipts": ["<seq>"],
    "audit_reports": ["<audit_id>"],
    "policy_proposals": ["<proposal_id>"]
  }
}

Rules:
- Cite specific evidence IDs for every claim in the timeline. Never claim
  "the agent did X" without an evidence_id pointing to the receipt that
  proves it.
- If evidence is insufficient, say so explicitly in the
  root_cause_hypothesis. Do not fabricate facts.
- severity is a judgment call. Err on the side of higher severity for
  ambiguous cases -- humans can downgrade.
- Output ONLY the JSON object. No preamble, no markdown code fences.
"""


def build_investigator_agent(db: firestore.Client, tenant: str,
                             model: str = "gemini-2.5-pro") -> LlmAgent:
    collector = EvidenceCollector(db)
    tools = make_adk_tools(collector, tenant)
    return LlmAgent(
        name="incident_investigator",
        model=model,
        instruction=INVESTIGATOR_INSTRUCTION,
        tools=tools,
        description=(
            "Security incident investigator. Synthesizes evidence from "
            "receipts, audit reports, and agent registrations into "
            "human-readable incident reports."
        ),
    )


def run_investigation(agent: LlmAgent, trigger: Dict) -> Optional[Dict]:
    """Run the agent with a trigger and return parsed incident narrative."""
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    trigger_type = trigger.get("type", "MANUAL")
    trigger_id = trigger.get("trigger_id", "unknown")

    prompt = (
        f"Investigate this security event.\n\n"
        f"Trigger type: {trigger_type}\n"
        f"Trigger ID: {trigger_id}\n"
    )
    if trigger_type == "AUDIT_CONFLICT":
        prompt += f"\nFetch audit report '{trigger_id}' and investigate the conflict.\n"
    elif trigger_type == "POLICY_PROPOSAL":
        prompt += f"\nFetch policy proposal '{trigger_id}' and investigate the pattern.\n"
    elif trigger_type == "MANUAL":
        extra = trigger.get("context", {})
        if extra:
            prompt += f"\nAdditional context: {json.dumps(extra, default=str)}\n"
        prompt += f"\nInvestigate artifact '{trigger_id}'.\n"

    try:
        import asyncio
        import concurrent.futures

        runner = InMemoryRunner(agent=agent, app_name="incident-investigator")
        user_id = "investigator-system"

        async def _create_and_run():
            session = await runner.session_service.create_session(
                app_name="incident-investigator", user_id=user_id
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
        logger.exception("Investigator agent invocation failed")
        return None

    cleaned = raw_output.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.startswith("json"):
            cleaned = cleaned[4:].strip()

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        logger.warning("Investigator returned non-JSON: %s", cleaned[:500])
        return None

    return parsed
