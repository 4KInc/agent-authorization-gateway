"""The Policy Auditor Agent — an ADK LlmAgent powered by Gemini 2.5 Pro.

Reads a single authorization receipt and assesses whether the gateway's
deterministic decision aligns with natural-language compliance frameworks
(OWASP NHI Top 10, NIST AI RMF, NIST SP 800-53).

The agent's verdict is its OPINION, not an authoritative override.
"""

from __future__ import annotations

import json
import logging
from typing import Dict, List, Tuple

from google.adk.agents import LlmAgent

from .compliance_search import ComplianceSearcher, make_adk_search_tool

logger = logging.getLogger(__name__)

AUDITOR_INSTRUCTION = """\
You are the Policy Auditor for a cryptographic agent authorization gateway.
Your job is to read a single authorization receipt and assess whether the
gateway's deterministic decision aligns with natural-language compliance
frameworks (OWASP Non-Human Identity Top 10, NIST AI RMF, NIST SP 800-53).

You are NOT replacing the gateway's decision. The gateway has already decided.
Your role is to produce a human-readable audit report that cross-references
that decision against compliance guidance, so a human reviewer can quickly see
whether the deterministic policy aligns with the natural-language frameworks
the organization claims to follow.

Procedure for every receipt:
1. Identify the salient facts: which agent, what action, what resource,
   what was the decision and reason codes.
2. Formulate AT LEAST TWO search queries, targeting different frameworks:

   Query A (NIST controls): use NIST SP 800-53 control language for any
   decision involving audit, access control, or system operations.
   Example: "audit event logging non-privileged read access"

   Query B (OWASP NHI): use OWASP Non-Human Identity language. EVERY
   receipt in this system involves a non-human identity (an AI agent),
   so this query is ALWAYS relevant.
   Example: "non-human identity authentication least privilege"

   Query C (optional, AI RMF): use when the receipt context involves AI
   system governance or risk.
   Example: "AI system access governance trustworthy"

   You MUST issue both Query A and Query B for every receipt. Bad queries
   are vague ("policy", "security"). Good queries name specific concepts
   from the framework vocabulary.

3. Read the extractive citations returned. They are verbatim passages
   from real PDFs. When you have relevant citations from multiple
   frameworks, INCLUDE ALL OF THEM. Cross-framework grounding strengthens
   the audit report. Do not collapse to a single source.
4. Produce a JSON object with this exact shape, and nothing else:

{
  "verdict": "ALIGNED" | "CONFLICT" | "INSUFFICIENT_EVIDENCE",
  "rationale": "<3-5 sentences explaining the verdict in plain language>",
  "citations": [
    {
      "source": "<source document name as returned by the tool>",
      "passage": "<the verbatim passage you cited>",
      "page": <integer or null>
    }
  ]
}

Verdict definitions:
- ALIGNED: The deterministic decision is consistent with the compliance
  guidance you found. Most receipts will be ALIGNED.
- CONFLICT: The deterministic decision appears to contradict explicit
  compliance guidance. This is rare and should be backed by a direct citation.
- INSUFFICIENT_EVIDENCE: No relevant compliance guidance found, or the
  guidance is too generic to assess this specific decision.

Rules:
- Cite ONLY passages the tool returned. Never invent a citation.
- If the tool returns [no_relevant_compliance_guidance_found] or
  [search_unavailable: ...], your verdict MUST be INSUFFICIENT_EVIDENCE.
- Keep rationale concise. 3-5 sentences. No marketing language.
- Output ONLY the JSON object. No preamble, no markdown code fences.
"""


def build_auditor_agent(searcher: ComplianceSearcher,
                        model: str = "gemini-2.5-pro") -> LlmAgent:
    return LlmAgent(
        name="policy_auditor",
        model=model,
        instruction=AUDITOR_INSTRUCTION,
        tools=[make_adk_search_tool(searcher)],
        description=(
            "Asynchronous compliance auditor. Reads receipts and "
            "cross-references against OWASP/NIST compliance PDFs via RAG."
        ),
    )


def audit_receipt(agent: LlmAgent, receipt: Dict) -> Tuple[str, str, List[Dict]]:
    """Run the agent on a single receipt. Returns (verdict, rationale, citations)."""
    import asyncio
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    prompt = (
        "Audit this receipt. Return ONLY the JSON object as specified.\n\n"
        f"Receipt:\n{json.dumps(receipt, default=str, indent=2)}"
    )

    try:
        import asyncio

        runner = InMemoryRunner(agent=agent, app_name="policy-auditor")
        user_id = "auditor-system"

        # create_session is async in ADK 2.1
        async def _create_and_run():
            session = await runner.session_service.create_session(
                app_name="policy-auditor", user_id=user_id
            )
            content = types.Content(
                role="user",
                parts=[types.Part.from_text(text=prompt)],
            )
            out = ""
            # runner.run() may be sync or async generator depending on ADK version
            events = runner.run(
                user_id=user_id,
                session_id=session.id,
                new_message=content,
            )
            # Handle both sync and async iterators
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

        # Run in a new event loop from a thread (avoids conflict with uvicorn's loop)
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            raw_output = pool.submit(asyncio.run, _create_and_run()).result(timeout=120)

    except Exception as e:
        logger.exception("Auditor agent invocation failed")
        return ("ERROR", f"Agent invocation failed: {e}", [])

    # Strip markdown fences defensively
    cleaned = raw_output.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.startswith("json"):
            cleaned = cleaned[4:].strip()

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as e:
        logger.warning("Auditor returned non-JSON: %s", cleaned[:500])
        return ("ERROR", f"Non-JSON output: {e}", [])

    verdict = parsed.get("verdict", "ERROR")
    if verdict not in ("ALIGNED", "CONFLICT", "INSUFFICIENT_EVIDENCE"):
        verdict = "ERROR"
    rationale = parsed.get("rationale", "")
    citations = parsed.get("citations", [])
    return (verdict, rationale, citations)
