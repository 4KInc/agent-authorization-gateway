"""MCP Server — exposes the Gateway as an MCP tool server.

Any agent framework (ADK, LangChain, CrewAI) can connect to this server
using the Model Context Protocol to authorize actions, verify receipts,
and inspect the receipt chain.

Run standalone:
    python -m gateway.mcp_server

Or mount alongside the REST API (see serve.py).
"""

from __future__ import annotations

import json
import os

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .gateway_service import GatewayService
from .store import create_store

# --- Singleton gateway + store ---
_gateway: GatewayService | None = None
_store = None


def _get_gateway() -> GatewayService:
    global _gateway
    if _gateway is None:
        _gateway = GatewayService(tenant="hackathon-demo")
    return _gateway


def _get_store():
    global _store
    if _store is None:
        _store = create_store()
    return _store


# --- MCP Server ---
mcp = FastMCP(
    "Agent Authorization Gateway",
    instructions=(
        "This MCP server provides cryptographic policy enforcement for AI agent actions. "
        "Use authorize_action before performing any privileged operation. "
        "Every decision (approve or deny) produces a signed, hash-chained receipt."
    ),
    transport_security=TransportSecuritySettings(
        # DNS rebinding protection: always enabled.
        # allowed_hosts includes localhost (for dev) + any deployed hostname
        # from MCP_ALLOWED_HOSTS env var (comma-separated).
        enable_dns_rebinding_protection=True,
        allowed_hosts=(
            ["127.0.0.1:*", "localhost:*", "[::1]:*"]
            + [h.strip() for h in os.environ.get("MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]
        ),
    ),
)


@mcp.tool()
async def authorize_action(
    agent_id: str,
    action: str,
    resource: str,
    agent_proof: str,
    parameters: str = "{}",
) -> str:
    """Evaluate an AI agent's intended action against a security policy.

    Returns an authorization decision (approve/deny) with a cryptographic
    receipt and, if approved, a 60-second scoped authorization token.

    SECURITY: agent_proof is REQUIRED. Calls without a valid DPoP proof
    signed by a registered agent key are rejected before policy evaluation.

    Args:
        agent_id: Unique identifier of the requesting agent.
        action: Human-readable description of the intended action.
        resource: Target resource (database, API endpoint, cloud service).
        agent_proof: DPoP-style proof JWT signed by the agent's Ed25519 private key.
        parameters: JSON string of action-specific parameters (optional).
    """
    params = None
    if parameters and parameters.strip():
        try:
            params = json.loads(parameters)
        except json.JSONDecodeError:
            params = {"raw": parameters}

    gateway = _get_gateway()
    store = _get_store()

    try:
        response = gateway.authorize(
            agent_id=agent_id,
            action=action,
            resource=resource,
            parameters=params,
            agent_proof=agent_proof,
        )
    except ValueError as e:
        error_code = str(e).split(":")[0] if ":" in str(e) else "IDENTITY_ERROR"
        return json.dumps({"error": error_code, "detail": str(e)})

    # Persist receipt with metadata — HARD FAILURE if this doesn't land.
    # A token without a persisted receipt is authorization without audit.
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
        await store.save_receipt(gateway.tenant, enriched)
        await store.save_stats(gateway.tenant, gateway.get_chain_stats())
    except Exception:
        import logging
        logging.getLogger("gateway.mcp_server").exception(
            "RECEIPT_PERSIST_FAILED: receipt not saved — token withheld"
        )
        return json.dumps({
            "error": "RECEIPT_PERSIST_FAILED",
            "detail": "Authorization succeeded but the receipt could not be persisted. "
                      "Token withheld to prevent authorization without audit trail.",
        })

    return json.dumps({
        "decision": response.decision,
        "reason_codes": response.reason_codes,
        "token": response.token,
        "receipt_hash": response.receipt_hash,
        "action_digest": response.action_digest,
    })


@mcp.tool()
def get_chain_stats() -> str:
    """Get statistics about the current receipt chain.

    Returns total receipts, approval/denial counts, Merkle root, and policy version.
    """
    return json.dumps(_get_gateway().get_chain_stats())


@mcp.tool()
def get_receipt_chain() -> str:
    """Get the full receipt chain for audit/verification.

    Returns all signed receipts in sequence order with hash chain linkage.
    """
    return json.dumps(_get_gateway().get_receipt_chain())


@mcp.tool()
def get_public_key() -> str:
    """Get the gateway's Ed25519 signing public key as a JWK.

    Any verifier can use this key to independently verify receipt signatures.
    """
    return json.dumps(_get_gateway().get_public_key_jwk())


@mcp.tool()
def verify_receipt(receipt_json: str) -> str:
    """Verify a receipt's cryptographic integrity and signature.

    Takes a receipt envelope as a JSON string and verifies:
    1. The canonical hash matches the claimed receipt_hash
    2. The Ed25519 signature is valid
    3. The receipt was not tampered with after signing

    Args:
        receipt_json: JSON string of the receipt envelope (body + sig + receipt_hash).
    """
    from .verify import verify_receipt as _verify

    try:
        envelope = json.loads(receipt_json)
    except json.JSONDecodeError:
        return json.dumps({"receipt_integrity": "FAIL", "errors": [{"code": "INVALID_JSON"}]})

    gateway = _get_gateway()
    result = _verify(envelope, gateway.get_public_key_jwk())
    return json.dumps(result.to_dict())


@mcp.tool()
def register_agent(agent_id: str, public_key_jwk: str) -> str:
    """Register an agent's Ed25519 public key for identity verification.

    After registration, the agent can create DPoP proofs that the Gateway
    verifies before authorizing actions. This must be called once before
    the first authorize_action call.

    Args:
        agent_id: Unique identifier for the agent.
        public_key_jwk: JSON string of the agent's Ed25519 public key as JWK.
    """
    try:
        jwk = json.loads(public_key_jwk)
    except json.JSONDecodeError:
        return json.dumps({"error": "INVALID_JSON", "detail": "public_key_jwk must be valid JSON"})

    gateway = _get_gateway()
    try:
        agent = gateway._registry.register(agent_id, jwk)
        return json.dumps({"status": "registered", "agent_id": agent.agent_id, "kid": agent.kid})
    except Exception as e:
        return json.dumps({"error": "REGISTRATION_FAILED", "detail": str(e)})


# --- Entry point ---
if __name__ == "__main__":
    import os
    os.environ.setdefault("FASTMCP_PORT", "8090")
    os.environ.setdefault("FASTMCP_HOST", "0.0.0.0")
    mcp.run(transport="streamable-http")
