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
from fastapi.responses import HTMLResponse
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
    try:
        gateway = _get_gateway()
        store = _get_store()

        # Resume chain from Firestore so new receipts continue the sequence
        stored_chain = await store.get_chain(gateway.tenant)
        if stored_chain:
            last = stored_chain[-1]
            last_seq = int(last.get("body", {}).get("seq", 0))
            last_hash = last.get("receipt_hash", "")
            if last_seq > 0 and last_hash:
                gateway._receipt_chain._seq = last_seq
                gateway._receipt_chain._prev_receipt_hash = last_hash
                print(f"[startup] Resumed chain at seq={last_seq}")

        # Merge this instance's key into the shared key set
        my_key = gateway.get_public_key_jwk()
        existing = await store.get_keys(gateway.tenant)
        all_keys = existing.get("keys", []) if existing else []
        known_kids = {k.get("kid") for k in all_keys}
        if my_key["kid"] not in known_kids:
            all_keys.append(my_key)
        await store.save_keys(gateway.tenant, {"tenant": gateway.tenant, "keys": all_keys})
    except Exception as e:
        print(f"[startup] Store init warning (non-fatal): {e}")
    yield


api_app = FastAPI(
    title="Agent Authorization Gateway",
    description="Cryptographic policy enforcement for AI agent actions",
    version="0.1.0",
    lifespan=lifespan,
)


@api_app.get("/", response_class=HTMLResponse)
async def root():
    """Interactive dashboard UI."""
    return _DASHBOARD_HTML


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

    # Persist receipt with action metadata for display
    # (the receipt body itself only stores the request_digest hash, not the original fields)
    enriched = {
        **response.receipt,
        "_meta": {
            "agent_id": req.agent_id,
            "action": req.action,
            "resource": req.resource,
            "parameters": req.parameters,
        },
    }
    try:
        await store.save_receipt(gateway.tenant, enriched)
        await store.save_stats(gateway.tenant, gateway.get_chain_stats())
    except Exception as e:
        print(f"[authorize] Persistence warning: {e}")

    return AuthorizeResponse(
        decision=response.decision,
        reason_codes=response.reason_codes,
        token=response.token,
        receipt=response.receipt,
        action_digest=response.action_digest,
        receipt_hash=response.receipt_hash,
    )


async def _resolve_key(req_key, receipt=None):
    """Resolve the public key to use for verification.

    Tries in order: explicit request key, key matching receipt kid from store, current instance key.
    """
    if req_key:
        return req_key
    gateway = _get_gateway()
    store = _get_store()
    # Try to find the key by kid from Firestore
    if receipt:
        receipt_kid = receipt.get("sig", {}).get("kid", "")
        if receipt_kid:
            try:
                stored = await store.get_keys(gateway.tenant)
                if stored:
                    for k in stored.get("keys", []):
                        if k.get("kid") == receipt_kid:
                            return k
            except Exception:
                pass
    return gateway.get_public_key_jwk()


@api_app.post("/verify-receipt", response_model=VerifyResponse)
async def verify_receipt_endpoint(req: VerifyReceiptRequest):
    """Verify a single receipt's integrity and signature.

    Any auditor can call this with a receipt envelope and the gateway's
    public key to independently verify the receipt was not tampered with.
    """
    public_key = await _resolve_key(req.public_key, req.receipt)
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
    store = _get_store()

    # Build a kid -> key lookup from all known keys in Firestore
    keys_by_kid = {}
    try:
        stored = await store.get_keys(gateway.tenant)
        if stored:
            for k in stored.get("keys", []):
                keys_by_kid[k.get("kid", "")] = k
    except Exception:
        pass
    # Always include current instance key
    my_key = gateway.get_public_key_jwk()
    keys_by_kid[my_key["kid"]] = my_key

    public_key = req.public_key or my_key
    result = verify_chain(req.receipts, public_key, keys_by_kid=keys_by_kid)

    return VerifyResponse(
        receipt_integrity=result.receipt_integrity,
        chain_validity=result.chain_validity,
        errors=result.errors,
    )


@api_app.get("/chain")
async def get_chain():
    """Get the full receipt chain for audit/verification."""
    gateway = _get_gateway()
    store = _get_store()

    # Try Firestore first for shared state across services
    stored_chain = await store.get_chain(gateway.tenant)
    if stored_chain:
        return {
            "tenant": gateway.tenant,
            "receipts": stored_chain,
            "count": len(stored_chain),
        }

    # Fall back to in-memory chain
    return {
        "tenant": gateway.tenant,
        "receipts": gateway.get_receipt_chain(),
        "count": len(gateway.get_receipt_chain()),
    }


@api_app.get("/stats", response_model=StatsResponse)
async def get_stats():
    """Get chain statistics — decision counts, Merkle root, policy version."""
    gateway = _get_gateway()
    store = _get_store()

    # Try Firestore first for shared state across services
    stored_stats = await store.get_stats(gateway.tenant)
    if stored_stats:
        stored_stats.pop("updated_at", None)
        # Ensure all required fields exist
        return StatsResponse(
            tenant=stored_stats.get("tenant", gateway.tenant),
            total_receipts=stored_stats.get("total_receipts", 0),
            approvals=stored_stats.get("approvals", 0),
            denials=stored_stats.get("denials", 0),
            merkle_root=stored_stats.get("merkle_root"),
            policy_version=stored_stats.get("policy_version", ""),
        )

    # Fall back to in-memory stats
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


# --- Dashboard HTML (served from separate file for maintainability) ---

def _load_dashboard_html() -> str:
    import pathlib
    p = pathlib.Path(__file__).parent / "dashboard.html"
    return p.read_text()

_DASHBOARD_HTML = _load_dashboard_html()
