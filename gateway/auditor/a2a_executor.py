"""A2A Executor for the Policy Auditor Agent.

Thin translation layer — all data access goes through Firestore reads against
existing collections written by auditor_service.py and report_writer.py.
No audit logic is duplicated here.
"""
from __future__ import annotations

import json
import logging

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events.event_queue_v2 import EventQueue
from a2a.types import Part, Task, TaskState, TaskStatus, Message

logger = logging.getLogger(__name__)


class AuditorA2AExecutor(AgentExecutor):
    """Executes Policy Auditor skills in response to A2A messages."""

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
        if skill == "query_audits":
            return self._query_audits(input_data)
        elif skill in ("audit_receipt", "explain_verdict"):
            return self._explain_verdict(input_data)
        elif skill == "help":
            return {
                "skills": ["query_audits", "audit_receipt", "explain_verdict"],
                "description": (
                    "Policy Auditor Agent — A2A surface. "
                    "Send {\"skill\": \"<name>\", \"input\": {...}} as a text message."
                ),
            }
        else:
            return {
                "error": "UNKNOWN_SKILL",
                "skill": skill,
                "available": ["query_audits", "audit_receipt", "explain_verdict"],
            }

    # ── Skill implementations ─────────────────────────────────────────────────

    def _query_audits(self, input_data: dict) -> dict:
        """Read audit reports from Firestore, filter by since_seq and verdict."""
        tenant = input_data.get("tenant", "default")
        since_seq = int(input_data.get("since_seq", 0))
        verdict_filter = input_data.get("verdict_filter")
        limit = int(input_data.get("limit", 50))

        collection = (
            self._db.collection("tenants")
            .document(tenant)
            .collection("audit_reports")
        )

        reports = []
        for doc in collection.stream():
            data = doc.to_dict()
            body = data.get("body", {})
            if body.get("receipt_seq", 0) <= since_seq:
                continue
            if verdict_filter and body.get("verdict") != verdict_filter:
                continue
            reports.append(data)

        reports.sort(key=lambda r: r.get("body", {}).get("receipt_seq", 0))
        return {"reports": reports[:limit], "count": len(reports[:limit])}

    def _explain_verdict(self, input_data: dict) -> dict:
        """Fetch a single audit report by audit_id from Firestore."""
        tenant = input_data.get("tenant", "default")
        audit_id = input_data.get("audit_id", "")

        if not audit_id:
            return {"error": "audit_id is required"}

        collection = (
            self._db.collection("tenants")
            .document(tenant)
            .collection("audit_reports")
        )

        for doc in collection.stream():
            data = doc.to_dict()
            body = data.get("body", {})
            if body.get("audit_id") == audit_id:
                return data

        return {"error": "AUDIT_NOT_FOUND", "audit_id": audit_id}
