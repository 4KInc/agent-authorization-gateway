"""HTTP API server — REST endpoints for authorization and verification.

Runs alongside the ADK agent, providing direct HTTP access for:
- POST /authorize — authorize an agent action
- POST /verify-receipt — verify a single receipt
- POST /verify-chain — verify a full receipt chain
- GET /chain — get the full receipt chain
- GET /stats — get chain statistics
- GET /keys — get the signing public key (JWK)
- GET /health — health check
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .gateway_service import GatewayService
from .store import ReceiptStore, create_store
from .verify import verify_chain, verify_receipt

# Module-level state
_gateway: GatewayService | None = None
_store: ReceiptStore | None = None


def _get_gateway() -> GatewayService:
    global _gateway
    if _gateway is None:
        _gateway = GatewayService(tenant="hackathon-demo")
    return _gateway


def _get_store() -> ReceiptStore:
    global _store
    if _store is None:
        _store = create_store()
    return _store


# --- Request/Response models ---

class AuthorizeRequest(BaseModel):
    agent_id: str
    action: str
    resource: str
    parameters: dict | None = None


class AuthorizeResponse(BaseModel):
    decision: str
    reason_codes: list[str]
    token: str | None = None
    receipt: dict
    action_digest: str
    receipt_hash: str


class VerifyReceiptRequest(BaseModel):
    receipt: dict = Field(..., description="Receipt envelope (body + sig + receipt_hash)")
    public_key: dict | None = Field(None, description="JWK public key. If omitted, uses gateway's key.")


class VerifyChainRequest(BaseModel):
    receipts: list[dict] = Field(..., description="Ordered list of receipt envelopes")
    public_key: dict | None = Field(None, description="JWK public key. If omitted, uses gateway's key.")


class VerifyResponse(BaseModel):
    receipt_integrity: str
    chain_validity: str = "INCONCLUSIVE"
    errors: list[dict] = []


class StatsResponse(BaseModel):
    tenant: str
    total_receipts: int
    approvals: int
    denials: int
    merkle_root: str | None
    policy_version: str


# --- API app ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: save initial keys to store
    gateway = _get_gateway()
    store = _get_store()
    keys = {
        "tenant": gateway.tenant,
        "keys": [gateway.get_public_key_jwk()],
    }
    await store.save_keys(gateway.tenant, keys)
    yield
    # Shutdown: nothing to clean up


api_app = FastAPI(
    title="Agent Authorization Gateway",
    description="Cryptographic policy enforcement for AI agent actions",
    version="0.1.0",
    lifespan=lifespan,
)


@api_app.get("/health")
async def health():
    gateway = _get_gateway()
    return {
        "status": "healthy",
        "tenant": gateway.tenant,
        "provider": "agent-authorization-gateway",
    }


@api_app.post("/authorize", response_model=AuthorizeResponse)
async def authorize(req: AuthorizeRequest):
    """Authorize an agent action. Returns decision + receipt + token."""
    gateway = _get_gateway()
    store = _get_store()

    response = gateway.authorize(
        agent_id=req.agent_id,
        action=req.action,
        resource=req.resource,
        parameters=req.parameters,
    )

    # Persist receipt
    await store.save_receipt(gateway.tenant, response.receipt)

    # Update stats
    await store.save_stats(gateway.tenant, gateway.get_chain_stats())

    return AuthorizeResponse(
        decision=response.decision,
        reason_codes=response.reason_codes,
        token=response.token,
        receipt=response.receipt,
        action_digest=response.action_digest,
        receipt_hash=response.receipt_hash,
    )


@api_app.post("/verify-receipt", response_model=VerifyResponse)
async def verify_receipt_endpoint(req: VerifyReceiptRequest):
    """Verify a single receipt's integrity and signature.

    Any auditor can call this with a receipt envelope and the gateway's
    public key to independently verify the receipt was not tampered with.
    """
    gateway = _get_gateway()
    public_key = req.public_key or gateway.get_public_key_jwk()

    result = verify_receipt(req.receipt, public_key)

    return VerifyResponse(
        receipt_integrity=result.receipt_integrity,
        chain_validity=result.chain_validity,
        errors=result.errors,
    )


@api_app.post("/verify-chain", response_model=VerifyResponse)
async def verify_chain_endpoint(req: VerifyChainRequest):
    """Verify a full receipt chain — integrity + sequence + hash linkage.

    Checks every receipt's signature, verifies sequence numbers are
    monotonic and dense, and confirms prev_receipt links form an
    unbroken hash chain from genesis.
    """
    gateway = _get_gateway()
    public_key = req.public_key or gateway.get_public_key_jwk()

    result = verify_chain(req.receipts, public_key)

    return VerifyResponse(
        receipt_integrity=result.receipt_integrity,
        chain_validity=result.chain_validity,
        errors=result.errors,
    )


@api_app.get("/chain")
async def get_chain():
    """Get the full receipt chain for audit/verification."""
    gateway = _get_gateway()
    return {
        "tenant": gateway.tenant,
        "receipts": gateway.get_receipt_chain(),
        "count": len(gateway.get_receipt_chain()),
    }


@api_app.get("/stats", response_model=StatsResponse)
async def get_stats():
    """Get chain statistics — decision counts, Merkle root, policy version."""
    gateway = _get_gateway()
    stats = gateway.get_chain_stats()
    return StatsResponse(**stats)


@api_app.get("/keys")
async def get_keys():
    """Get the gateway's signing public key as a JWK.

    Any verifier can use this key to independently verify receipt signatures
    without trusting the gateway.
    """
    gateway = _get_gateway()
    return {
        "tenant": gateway.tenant,
        "keys": [gateway.get_public_key_jwk()],
    }
