"""ADK tool: authorize_action

Exposes the Gateway Service as a callable tool for AI agents.
Any agent (ADK, LangChain, CrewAI) can call this via MCP or direct invocation.
"""

from __future__ import annotations

from google.adk.tools import FunctionTool

from ..gateway_service import GatewayService

# Module-level gateway instance (initialized once per process)
_gateway: GatewayService | None = None


def _get_gateway() -> GatewayService:
    global _gateway
    if _gateway is None:
        _gateway = GatewayService(tenant="hackathon-demo")
    return _gateway


def authorize_action(
    agent_id: str,
    action: str,
    resource: str,
    parameters: str = "",
) -> dict:
    """Evaluate an AI agent's intended action against a security policy.

    Returns an authorization decision (approve/deny) with a cryptographic
    receipt and, if approved, a 60-second scoped authorization token.

    Args:
        agent_id: Unique identifier of the requesting agent.
        action: Human-readable description of the intended action.
        resource: Target resource (database, API endpoint, cloud service).
        parameters: JSON string of action-specific parameters (optional).

    Returns:
        dict with decision, reason_codes, token (if approved), receipt, and action_digest.
    """
    import json
    params = None
    if parameters and parameters.strip():
        try:
            params = json.loads(parameters)
        except json.JSONDecodeError:
            params = {"raw": parameters}

    gateway = _get_gateway()
    response = gateway.authorize(
        agent_id=agent_id,
        action=action,
        resource=resource,
        parameters=params,
    )

    return {
        "decision": response.decision,
        "reason_codes": response.reason_codes,
        "token": response.token,
        "receipt": response.receipt,
        "action_digest": response.action_digest,
        "receipt_hash": response.receipt_hash,
    }


def get_chain_stats() -> dict:
    """Get statistics about the current receipt chain.

    Returns total receipts, approval/denial counts, Merkle root, and policy version.
    """
    return _get_gateway().get_chain_stats()


def get_receipt_chain() -> list[dict]:
    """Get the full receipt chain for audit/verification.

    Returns all signed receipts in sequence order with hash chain linkage.
    """
    return _get_gateway().get_receipt_chain()


def get_public_key() -> dict:
    """Get the gateway's signing public key as a JWK.

    Any verifier can use this key to independently verify receipt signatures.
    """
    return _get_gateway().get_public_key_jwk()


# Export as ADK FunctionTools
authorize_action_tool = FunctionTool(authorize_action)
get_chain_stats_tool = FunctionTool(get_chain_stats)
get_receipt_chain_tool = FunctionTool(get_receipt_chain)
get_public_key_tool = FunctionTool(get_public_key)
