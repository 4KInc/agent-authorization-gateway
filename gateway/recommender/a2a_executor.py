"""A2A Executor for the Policy Recommendation Agent.

Thin translation layer — all data access goes through Firestore reads against
existing collections written by recommender_service.py and proposal_writer.py.
No recommendation logic is duplicated here.
"""
from __future__ import annotations

import json
import logging

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events.event_queue_v2 import EventQueue
from a2a.types import Part, Task, TaskState, TaskStatus, Message

logger = logging.getLogger(__name__)


class RecommenderA2AExecutor(AgentExecutor):
    """Executes Policy Recommender skills in response to A2A messages."""

    def __init__(self):
        self._db = None

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        pass

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        user_text = ""
        msg = context.message
        if msg:
            for part in msg.parts:
                if part.text:
                    user_text += part.text

        if not user_text:
            user_text = context.get_user_input("\n")

        if not user_text:
            await event_queue.enqueue_event(Task(
                id=context.task_id,
                context_id=context.context_id,
                status=TaskStatus(
                    state=TaskState.TASK_STATE_COMPLETED,
                    message=Message(
                        role="ROLE_AGENT",
                        parts=[Part(text="No message received.")],
                        message_id=context.task_id + "-r",
                    ),
                ),
            ))
            return

        try:
            request = json.loads(user_text)
        except json.JSONDecodeError:
            request = {"skill": "help", "input": {"query": user_text}}

        skill = request.get("skill", "help")
        skill_input = request.get("input", {})

        try:
            result = self._dispatch_skill(skill, skill_input)
            response_text = json.dumps(result, indent=2, default=str)
        except Exception as e:
            logger.exception("Skill %s failed", skill)
            response_text = json.dumps({"error": str(e)})

        await event_queue.enqueue_event(Task(
            id=context.task_id,
            context_id=context.context_id,
            status=TaskStatus(
                state=TaskState.TASK_STATE_COMPLETED,
                message=Message(
                    role="ROLE_AGENT",
                    parts=[Part(text=response_text)],
                    message_id=context.task_id + "-r",
                ),
            ),
        ))

    # ── Skill dispatch ────────────────────────────────────────────────────────

    def _dispatch_skill(self, skill: str, input_data: dict) -> dict:
        if skill == "query_proposals":
            return self._query_proposals(input_data)
        elif skill == "explain_proposal":
            return self._explain_proposal(input_data)
        elif skill == "help":
            return {
                "skills": ["query_proposals", "explain_proposal"],
                "description": (
                    "Policy Recommendation Agent — A2A surface. "
                    "Send {\"skill\": \"<name>\", \"input\": {...}} as a text message."
                ),
            }
        else:
            return {
                "error": "UNKNOWN_SKILL",
                "skill": skill,
                "available": ["query_proposals", "explain_proposal"],
            }

    # ── Skill implementations ─────────────────────────────────────────────────

    def _query_proposals(self, input_data: dict) -> dict:
        """Read policy proposals from Firestore for a given tenant."""
        tenant = input_data.get("tenant", "default")
        limit = int(input_data.get("limit", 20))

        collection = (
            self._db.collection("tenants")
            .document(tenant)
            .collection("policy_proposals")
        )

        proposals = []
        for doc in collection.stream():
            proposals.append(doc.to_dict())

        proposals.sort(
            key=lambda p: p.get("body", {}).get("proposed_at", ""),
            reverse=True,
        )
        return {"proposals": proposals[:limit], "count": len(proposals[:limit])}

    def _explain_proposal(self, input_data: dict) -> dict:
        """Fetch a single proposal envelope by proposal_id from Firestore."""
        tenant = input_data.get("tenant", "default")
        proposal_id = input_data.get("proposal_id", "")

        if not proposal_id:
            return {"error": "proposal_id is required"}

        collection = (
            self._db.collection("tenants")
            .document(tenant)
            .collection("policy_proposals")
        )

        for doc in collection.stream():
            data = doc.to_dict()
            body = data.get("body", {})
            if body.get("proposal_id") == proposal_id:
                return data

        return {"error": "PROPOSAL_NOT_FOUND", "proposal_id": proposal_id}
