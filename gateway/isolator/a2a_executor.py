"""A2A Executor for the Isolator Agent.

Thin translation layer -- reads isolation records from Firestore.
Containment triggering is delegated to the REST /isolate endpoint.
"""
from __future__ import annotations

import json
import logging

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events.event_queue_v2 import EventQueue
from a2a.types import Part, Task, TaskState, TaskStatus, Message

logger = logging.getLogger(__name__)


class IsolatorA2AExecutor(AgentExecutor):
    """Executes Isolator skills in response to A2A messages."""

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

    def _dispatch_skill(self, skill: str, input_data: dict) -> dict:
        if skill == "query_isolation_records":
            return self._query_records(input_data)
        elif skill == "explain_isolation":
            return self._explain_isolation(input_data)
        elif skill == "isolate_agent":
            return {
                "info": "Containment must be triggered via POST /isolate on the REST surface.",
                "reason": "A2A transport cannot enforce the severity-gated containment flow.",
            }
        elif skill == "help":
            return {
                "skills": ["query_isolation_records", "explain_isolation", "isolate_agent"],
                "description": (
                    "Isolator Agent -- A2A surface. "
                    "Send {\"skill\": \"<name>\", \"input\": {...}} as a text message."
                ),
            }
        else:
            return {
                "error": "UNKNOWN_SKILL",
                "skill": skill,
                "available": ["query_isolation_records", "explain_isolation", "isolate_agent"],
            }

    def _query_records(self, input_data: dict) -> dict:
        tenant = input_data.get("tenant", "default")
        limit = int(input_data.get("limit", 20))

        collection = (
            self._db.collection("tenants")
            .document(tenant)
            .collection("isolation_records")
        )

        records = []
        for doc in collection.stream():
            records.append(doc.to_dict())

        records.sort(
            key=lambda r: r.get("body", {}).get("isolated_at", ""),
            reverse=True,
        )
        return {"isolation_records": records[:limit], "count": min(len(records), limit)}

    def _explain_isolation(self, input_data: dict) -> dict:
        tenant = input_data.get("tenant", "default")
        isolation_id = input_data.get("isolation_id", "")

        if not isolation_id:
            return {"error": "isolation_id is required"}

        collection = (
            self._db.collection("tenants")
            .document(tenant)
            .collection("isolation_records")
        )

        for doc in collection.stream():
            data = doc.to_dict()
            body = data.get("body", {})
            if body.get("isolation_id") == isolation_id:
                return data

        return {"error": "ISOLATION_NOT_FOUND", "isolation_id": isolation_id}
