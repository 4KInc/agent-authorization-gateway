"""A2A Executor for the Investigation Agent.

Thin translation layer — all data access goes through Firestore reads against
existing collections written by investigator_service.py and incident_writer.py.
No investigation logic is duplicated here.
"""
from __future__ import annotations

import json
import logging

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events.event_queue_v2 import EventQueue
from a2a.types import Part, Task, TaskState, TaskStatus, Message

logger = logging.getLogger(__name__)

# Severity ordering for filtering (highest to lowest)
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class InvestigatorA2AExecutor(AgentExecutor):
    """Executes Investigation Agent skills in response to A2A messages."""

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
        if skill == "query_incidents":
            return self._query_incidents(input_data)
        elif skill == "explain_incident":
            return self._explain_incident(input_data)
        elif skill == "help":
            return {
                "skills": ["query_incidents", "explain_incident"],
                "description": (
                    "Investigation Agent — A2A surface. "
                    "Send {\"skill\": \"<name>\", \"input\": {...}} as a text message."
                ),
            }
        else:
            return {
                "error": "UNKNOWN_SKILL",
                "skill": skill,
                "available": ["query_incidents", "explain_incident"],
            }

    # ── Skill implementations ─────────────────────────────────────────────────

    def _query_incidents(self, input_data: dict) -> dict:
        """Read incident reports from Firestore, optionally filtered by severity."""
        tenant = input_data.get("tenant", "default")
        severity_filter = input_data.get("severity")
        limit = int(input_data.get("limit", 20))

        collection = (
            self._db.collection("tenants")
            .document(tenant)
            .collection("incident_reports")
        )

        reports = []
        for doc in collection.stream():
            data = doc.to_dict()
            body = data.get("body", {})
            if severity_filter:
                # Include incidents at or above the requested severity
                incident_severity = body.get("severity", "INFO")
                req_idx = _SEVERITY_ORDER.index(severity_filter) if severity_filter in _SEVERITY_ORDER else len(_SEVERITY_ORDER)
                inc_idx = _SEVERITY_ORDER.index(incident_severity) if incident_severity in _SEVERITY_ORDER else len(_SEVERITY_ORDER)
                if inc_idx > req_idx:
                    continue
            reports.append(data)

        reports.sort(
            key=lambda r: r.get("body", {}).get("created_at", ""),
            reverse=True,
        )
        return {"incidents": reports[:limit], "count": len(reports[:limit])}

    def _explain_incident(self, input_data: dict) -> dict:
        """Fetch a single incident report by incident_id from Firestore."""
        tenant = input_data.get("tenant", "default")
        incident_id = input_data.get("incident_id", "")

        if not incident_id:
            return {"error": "incident_id is required"}

        collection = (
            self._db.collection("tenants")
            .document(tenant)
            .collection("incident_reports")
        )

        for doc in collection.stream():
            data = doc.to_dict()
            body = data.get("body", {})
            if body.get("incident_id") == incident_id:
                return data

        return {"error": "INCIDENT_NOT_FOUND", "incident_id": incident_id}
