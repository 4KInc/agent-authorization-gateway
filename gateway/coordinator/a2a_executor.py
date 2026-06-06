"""A2A Executor for the Discovery Coordinator Agent.

Thin translation layer:
- list_known_agents: reads directly from Firestore via directory.list_entries
- route_capability: proxies to the coordinator REST service POST /route-question
- register_known_agent: proxies to the coordinator REST service POST /discover

HTTP proxying uses httpx (sync). The coordinator REST URL is read from
COORDINATOR_REST_URL env var (default: http://localhost:8000).
"""
from __future__ import annotations

import json
import logging
import os

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events.event_queue_v2 import EventQueue
from a2a.types import Part, Task, TaskState, TaskStatus, Message

logger = logging.getLogger(__name__)


def _coordinator_rest_url() -> str:
    return os.environ.get("COORDINATOR_REST_URL", "http://localhost:8000").rstrip("/")


class CoordinatorA2AExecutor(AgentExecutor):
    """Executes Discovery Coordinator skills in response to A2A messages."""

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
        if skill == "route_capability":
            return self._route_capability(input_data)
        elif skill == "list_known_agents":
            return self._list_known_agents(input_data)
        elif skill == "register_known_agent":
            return self._register_known_agent(input_data)
        elif skill == "help":
            return {
                "skills": ["route_capability", "list_known_agents", "register_known_agent"],
                "description": (
                    "Discovery Coordinator Agent — A2A surface. "
                    "Send {\"skill\": \"<name>\", \"input\": {...}} as a text message."
                ),
            }
        else:
            return {
                "error": "UNKNOWN_SKILL",
                "skill": skill,
                "available": ["route_capability", "list_known_agents", "register_known_agent"],
            }

    # ── Skill implementations ─────────────────────────────────────────────────

    def _list_known_agents(self, input_data: dict) -> dict:
        """Read all known agents from the Firestore directory."""
        from .directory import list_entries
        entries = list_entries(self._db)
        return {"agents": entries, "count": len(entries)}

    def _route_capability(self, input_data: dict) -> dict:
        """Proxy to coordinator REST POST /route-question."""
        import httpx

        question = input_data.get("question", "")
        if not question:
            return {"error": "question is required"}

        base_url = _coordinator_rest_url()
        try:
            resp = httpx.post(
                f"{base_url}/route-question",
                json={"question": question},
                timeout=30.0,
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            logger.error("route-question HTTP error: %s", e)
            return {"error": f"HTTP {e.response.status_code}", "detail": e.response.text}
        except Exception as e:
            logger.exception("route-question failed")
            return {"error": str(e)}

    def _register_known_agent(self, input_data: dict) -> dict:
        """Proxy to coordinator REST POST /discover."""
        import httpx

        agent_card_url = input_data.get("agent_card_url", "")
        if not agent_card_url:
            return {"error": "agent_card_url is required"}

        payload: dict = {"agent_card_url": agent_card_url}
        introducer = input_data.get("introducer")
        if introducer:
            payload["introducer"] = introducer

        base_url = _coordinator_rest_url()
        try:
            resp = httpx.post(
                f"{base_url}/discover",
                json=payload,
                timeout=30.0,
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            logger.error("discover HTTP error: %s", e)
            return {"error": f"HTTP {e.response.status_code}", "detail": e.response.text}
        except Exception as e:
            logger.exception("discover failed")
            return {"error": str(e)}
