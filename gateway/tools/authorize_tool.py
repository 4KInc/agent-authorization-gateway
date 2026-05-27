"""ADK tool: authorize_action

Exposes the Gateway Service as a callable tool for AI agents.
Any agent (ADK, LangChain, CrewAI) can call this via MCP or direct invocation.
Persists receipts to the configured store (Firestore or in-memory).
"""

from __future__ import annotations

import asyncio

from google.adk.tools import FunctionTool

from ..gateway_service import GatewayService
from ..store import ReceiptStore, create_store

# Module-level gateway + store (initialized once per process)
_gateway: GatewayService | None = None
_store: ReceiptStore | None = None


def _get_gateway() -> GatewayService:
    global _gateway
    if _gateway is None:
        _gateway = GatewayService(tenant="hackathon-demo")
        # Resume chain from store if available
        try:
            store = _get_store()
            chain = _run_async(store.get_chain(_gateway.tenant))
            if chain:
                last = chain[-1]
                last_seq = int(last.get("body", {}).get("seq", 0))
                last_hash = last.get("receipt_hash", "")
                if last_seq > 0 and last_hash:
                    _gateway._receipt_chain._seq = last_seq
                    _gateway._receipt_chain._prev_receipt_hash = last_hash
                    print(f"[adk-tool] Resumed chain at seq={last_seq}")
        except Exception:
            pass
    return _gateway


def _get_store() -> ReceiptStore:
    global _store
    if _store is None:
        _store = create_store()
    return _store


def _run_async(coro):
    """Run an async coroutine from sync context."""
    try:
        loop = asyncio.get_running_loop()
        # If we're already in an async context, create a task
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        return asyncio.run(coro)


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
    store = _get_store()

    response = gateway.authorize(
        agent_id=agent_id,
        action=action,
        resource=resource,
        parameters=params,
    )

    # Persist receipt with action metadata for display
    enriched = {
        **response.receipt,
        "_meta": {
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "parameters": params,
        },
    }
    try:
        _run_async(store.save_receipt(gateway.tenant, enriched))
        _run_async(store.save_stats(gateway.tenant, gateway.get_chain_stats()))
    except Exception:
        pass  # Don't fail authorization if persistence fails

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


def verify_receipt_tool_fn(receipt_json: str) -> dict:
    """Verify a receipt's cryptographic integrity and signature.

    Takes a receipt envelope as a JSON string and verifies:
    1. The canonical hash matches the claimed receipt_hash
    2. The Ed25519 signature is valid
    3. The receipt was not tampered with after signing

    Args:
        receipt_json: JSON string of the receipt envelope (body + sig + receipt_hash).

    Returns:
        Verification result with receipt_integrity status and any errors.
    """
    import json
    from ..verify import verify_receipt as _verify

    try:
        envelope = json.loads(receipt_json)
    except json.JSONDecodeError:
        return {"receipt_integrity": "FAIL", "errors": [{"code": "INVALID_JSON", "message": "Could not parse receipt JSON"}]}

    gateway = _get_gateway()
    result = _verify(envelope, gateway.get_public_key_jwk())
    return result.to_dict()


# Export as ADK FunctionTools
authorize_action_tool = FunctionTool(authorize_action)
get_chain_stats_tool = FunctionTool(get_chain_stats)
get_receipt_chain_tool = FunctionTool(get_receipt_chain)
get_public_key_tool = FunctionTool(get_public_key)
verify_receipt_adk_tool = FunctionTool(verify_receipt_tool_fn)
