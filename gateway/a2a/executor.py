"""A2A AgentExecutor — dispatches A2A messages to GatewayService skills.

The A2A surface is a thin translation layer. ALL authorization logic stays
in GatewayService.authorize(). This executor translates A2A message envelopes
into GatewayService calls and wraps responses back into A2A format.
"""

from __future__ import annotations

import json
import logging

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events.event_queue_v2 import EventQueue
from a2a.types import Part, Task, TaskState, TaskStatus, Message

logger = logging.getLogger(__name__)


class GatewayA2AExecutor(AgentExecutor):
    """Executes gateway skills in response to A2A messages."""

    def __init__(self, gateway_service=None, store=None):
        self._gw = gateway_service
        self._store = store

    @property
    def _gateway(self):
        return self._gw

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Cancel is a no-op for synchronous skills."""
        pass

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Process an A2A request and publish results to the event queue."""
        # Extract the user's message from the context
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
                    message=Message(role="ROLE_AGENT", parts=[Part(text="No message received.")], message_id=context.task_id + "-r"),
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
                message=Message(role="ROLE_AGENT", parts=[Part(text=response_text)], message_id=context.task_id + "-r"),
            ),
        ))

    def _dispatch_skill(self, skill: str, input_data: dict) -> dict:
        """Route to the appropriate GatewayService method."""
        if skill == "get_public_key":
            return self._gateway.get_public_key_jwk()

        elif skill == "get_chain_summary":
            stats = self._gateway.get_chain_stats()
            return stats

        elif skill == "verify_receipt":
            from gateway.verify import verify_receipt as _verify
            receipt_seq = input_data.get("receipt_seq")
            chain = self._gateway.get_receipt_chain()
            receipt = None
            for r in chain:
                if str(r.get("body", {}).get("seq")) == str(receipt_seq):
                    receipt = r
                    break
            if not receipt:
                return {"error": "RECEIPT_NOT_FOUND", "seq": receipt_seq}
            result = _verify(receipt, self._gateway.get_public_key_jwk(), chain=chain)
            return result.to_dict()

        elif skill == "authorize_action":
            agent_id = input_data.get("agent_id")
            action = input_data.get("action")
            resource = input_data.get("resource")
            agent_proof = input_data.get("agent_proof", "")
            parameters = input_data.get("parameters")

            if not agent_proof:
                return {"error": "NO_PROOF", "detail": "agent_proof is required for authorize_action over A2A"}

            try:
                resp = self._gateway.authorize(
                    agent_id=agent_id,
                    action=action,
                    resource=resource,
                    agent_proof=agent_proof,
                    parameters=parameters,
                )
                return {
                    "decision": resp.decision,
                    "reason_codes": resp.reason_codes,
                    "token": resp.token,
                    "receipt_hash": resp.receipt_hash,
                    "action_digest": resp.action_digest,
                }
            except ValueError as e:
                error_code = str(e).split(":")[0]
                return {"error": error_code, "detail": str(e)}

        elif skill == "help":
            return {
                "skills": ["authorize_action", "verify_receipt", "get_public_key", "get_chain_summary"],
                "description": "Agent Authorization Gateway — A2A surface. Send {\"skill\": \"<name>\", \"input\": {...}} as a text message.",
            }

        else:
            return {"error": "UNKNOWN_SKILL", "skill": skill, "available": ["authorize_action", "verify_receipt", "get_public_key", "get_chain_summary"]}
