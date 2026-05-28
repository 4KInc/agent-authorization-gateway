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

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator

from .anchor import AnchorRecord, AnchorSink, create_anchor_sink
from .gateway_service import GatewayService
from .identity import AgentRegistry, verify_agent_proof
from .store import ReceiptStore, create_store
from .verify import verify_chain, verify_receipt

logger = logging.getLogger("gateway.api")
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)

# Module-level state
_gateway: GatewayService | None = None
_store: ReceiptStore | None = None
_anchor: AnchorSink | None = None
_registry = AgentRegistry()


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


def _get_anchor() -> AnchorSink:
    global _anchor
    if _anchor is None:
        _anchor = create_anchor_sink()
    return _anchor


# --- Request/Response models ---

class AuthorizeRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=256, description="Unique agent identifier")
    action: str = Field(..., min_length=1, max_length=256, description="Action to authorize")
    resource: str = Field(..., min_length=1, max_length=512, description="Target resource")
    parameters: dict | None = None
    agent_proof: str | None = Field(None, description="DPoP-style agent identity proof JWT (optional)")

    @field_validator("agent_id", "action", "resource")
    @classmethod
    def no_empty_whitespace(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be empty or whitespace-only")
        return v.strip()


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

        # Load policy from Firestore if available (runtime-configurable policies)
        stored_policy = await store.get_policy(gateway.tenant)
        if stored_policy and "rules" in stored_policy:
            from .policy import Policy, PolicyRule, PolicyEngine
            rules = [PolicyRule(id=r["id"], type=r["type"], config=r["config"]) for r in stored_policy["rules"]]
            policy = Policy(rules=rules, version=stored_policy.get("version", "1"))
            gateway.policy = policy
            gateway._policy_engine = PolicyEngine(policy)
            logger.info(f"Loaded policy from Firestore: {len(rules)} rules, hash={policy.policy_hash()[:24]}")
        else:
            # Save default policy to Firestore for future editing
            demo = gateway.policy
            await store.save_policy(gateway.tenant, {
                "version": demo.version,
                "rules": [{"id": r.id, "type": r.type, "config": r.config} for r in demo.rules],
            })
            logger.info("Saved default policy to Firestore")

        # Restore rate limit counters from Firestore (survives restarts)
        stored_rates = await store.get_rate_limits(gateway.tenant)
        if stored_rates:
            stored_rates.pop("updated_at", None)
            # Convert stored timestamps back to float lists
            for key, timestamps in stored_rates.items():
                if isinstance(timestamps, list):
                    gateway._policy_engine._rate_counters[key] = timestamps
            logger.info(f"Restored rate limit counters: {len(stored_rates)} keys")

        # Resume chain from Firestore so new receipts continue the sequence
        stored_chain = await store.get_chain(gateway.tenant)
        if stored_chain:
            last = stored_chain[-1]
            last_seq = int(last.get("body", {}).get("seq", 0))
            last_hash = last.get("receipt_hash", "")
            if last_seq > 0 and last_hash:
                gateway._receipt_chain._seq = last_seq
                gateway._receipt_chain._prev_receipt_hash = last_hash
                logger.info(f"Resumed chain at seq={last_seq}")

        # Merge this instance's key into the shared key set
        my_key = gateway.get_public_key_jwk()
        existing = await store.get_keys(gateway.tenant)
        all_keys = existing.get("keys", []) if existing else []
        known_kids = {k.get("kid") for k in all_keys}
        if my_key["kid"] not in known_kids:
            all_keys.append(my_key)
        await store.save_keys(gateway.tenant, {"tenant": gateway.tenant, "keys": all_keys})
    except Exception as e:
        logger.warning(f"Store init (non-fatal): {e}")
    yield


api_app = FastAPI(
    title="Agent Authorization Gateway",
    description="Cryptographic policy enforcement for AI agent actions",
    version="0.1.0",
    lifespan=lifespan,
)

api_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@api_app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration_ms = round((time.time() - start) * 1000)
    logger.info(f"{request.method} {request.url.path} {response.status_code} {duration_ms}ms")
    return response


@api_app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "internal_server_error", "detail": "An unexpected error occurred."},
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
    """Authorize an agent action. Returns decision + receipt + token.

    If agent_proof is provided, the Gateway verifies the agent's identity
    before evaluating the policy. This binds the decision to a verified agent.
    """
    gateway = _get_gateway()
    store = _get_store()

    # Verify agent identity proof if provided
    verified_agent = None
    if req.agent_proof:
        try:
            verified_agent = verify_agent_proof(
                proof=req.agent_proof,
                registry=_registry,
                expected_agent_id=req.agent_id,
                expected_action=req.action,
                expected_resource=req.resource,
            )
            logger.info(f"Agent identity verified: {verified_agent.agent_id} kid={verified_agent.kid}")
        except ValueError as e:
            raise HTTPException(401, str(e))

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
        await store.save_rate_limits(gateway.tenant, gateway._policy_engine._rate_counters)
    except Exception as e:
        logger.warning(f"Persistence warning: {e}")

    # Anchor Merkle root
    try:
        merkle_root = gateway.get_merkle_root()
        if merkle_root:
            anchor = _get_anchor()
            record = AnchorRecord(
                merkle_root=merkle_root,
                receipt_count=len(gateway._receipt_chain.get_receipts()),
                tenant=gateway.tenant,
            )
            await anchor.anchor(record, gateway._private_key)
    except Exception as e:
        logger.warning(f"Anchor warning: {e}")

    logger.info(f"authorize: agent={req.agent_id} action={req.action} resource={req.resource} decision={response.decision}")

    return AuthorizeResponse(
        decision=response.decision,
        reason_codes=response.reason_codes,
        token=response.token,
        receipt=response.receipt,
        action_digest=response.action_digest,
        receipt_hash=response.receipt_hash,
    )


@api_app.post("/authorize/dry-run")
async def authorize_dry_run(req: AuthorizeRequest):
    """Simulate an authorization without creating a receipt or token.

    Evaluates the policy and returns what the decision would be,
    without signing a receipt or advancing the chain. Useful for
    testing policy changes before applying them.
    """
    gateway = _get_gateway()
    result = gateway._policy_engine.evaluate(
        agent_id=req.agent_id,
        action=req.action,
        resource=req.resource,
        parameters=req.parameters,
    )
    return {
        "decision": result.decision,
        "reason_codes": result.reason_codes,
        "dry_run": True,
        "policy_version": gateway.policy.policy_hash(),
    }


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


@api_app.get("/policy")
async def get_policy():
    """Get the current security policy."""
    gateway = _get_gateway()
    return {
        "tenant": gateway.tenant,
        "version": gateway.policy.version,
        "policy_hash": gateway.policy.policy_hash(),
        "rules": [
            {"id": r.id, "type": r.type, "config": r.config}
            for r in gateway.policy.rules
        ],
    }


class UpdatePolicyRequest(BaseModel):
    version: str = Field(default="1", description="Policy version")
    rules: list[dict] = Field(..., description="List of policy rules")


@api_app.put("/policy")
async def update_policy(req: UpdatePolicyRequest):
    """Update the security policy at runtime.

    Policy changes take effect immediately and are persisted to Firestore.
    The new policy hash is bound to all subsequent receipts.
    """
    from .policy import Policy, PolicyRule, PolicyEngine

    gateway = _get_gateway()
    store = _get_store()

    rules = []
    for r in req.rules:
        if not r.get("id") or not r.get("type"):
            raise HTTPException(400, f"Each rule must have 'id' and 'type' fields")
        rules.append(PolicyRule(id=r["id"], type=r["type"], config=r.get("config", {})))

    policy = Policy(rules=rules, version=req.version)
    gateway.policy = policy
    gateway._policy_engine = PolicyEngine(policy)

    try:
        await store.save_policy(gateway.tenant, {
            "version": req.version,
            "rules": req.rules,
        })
    except Exception as e:
        logger.warning(f"Policy persistence warning: {e}")

    logger.info(f"Policy updated: {len(rules)} rules, hash={policy.policy_hash()[:24]}")
    return {
        "status": "updated",
        "policy_hash": policy.policy_hash(),
        "rule_count": len(rules),
    }


class AgentRegisterRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=256)
    public_key: dict = Field(..., description="Agent's Ed25519 public key as JWK")


@api_app.post("/agents/register")
async def register_agent(req: AgentRegisterRequest):
    """Register an agent's public key for identity verification.

    After registration, the agent can sign DPoP-style proofs that
    the Gateway verifies before authorizing actions. This binds
    authorization decisions to a specific verified identity.
    """
    try:
        agent = _registry.register(req.agent_id, req.public_key)
        return {
            "status": "registered",
            "agent_id": agent.agent_id,
            "kid": agent.kid,
        }
    except Exception as e:
        raise HTTPException(400, f"Registration failed: {e}")


@api_app.get("/agents")
async def list_agents():
    """List all registered agents."""
    return {"agents": _registry.list_agents()}


@api_app.get("/anchors")
async def get_anchors():
    """Get all Merkle root anchors for the tenant."""
    gateway = _get_gateway()
    anchor = _get_anchor()
    anchors = await anchor.get_anchors(gateway.tenant)
    return {"tenant": gateway.tenant, "anchors": anchors, "count": len(anchors)}


@api_app.post("/tamper-test")
async def tamper_test(receipt_index: int = 0, field: str = "decision"):
    """DEV ONLY: Tamper with a receipt in the in-memory chain to demonstrate detection.

    Modifies the specified field of the receipt at the given index.
    Only available when GATEWAY_DEV_MODE=true.
    """
    import os
    if os.environ.get("GATEWAY_DEV_MODE", "").lower() != "true":
        raise HTTPException(403, "Tamper test only available in dev mode (GATEWAY_DEV_MODE=true)")

    gateway = _get_gateway()
    receipts = gateway._receipt_chain._receipts

    if not receipts or receipt_index >= len(receipts):
        raise HTTPException(400, f"Invalid receipt index {receipt_index}, chain has {len(receipts)} receipts")

    receipt = receipts[receipt_index]
    original_value = getattr(receipt, field, None)
    if original_value is None:
        raise HTTPException(400, f"Field '{field}' not found in receipt")

    # Tamper: modify the field directly on the Receipt object
    if isinstance(original_value, str):
        setattr(receipt, field, original_value + "-TAMPERED")
    elif isinstance(original_value, list):
        setattr(receipt, field, original_value + ["TAMPERED"])
    else:
        setattr(receipt, field, "TAMPERED")

    new_value = getattr(receipt, field)

    # Also tamper the store copy so /chain returns the tampered data
    store = _get_store()
    try:
        stored_chain = await store.get_chain(gateway.tenant)
        if stored_chain and receipt_index < len(stored_chain):
            stored_chain[receipt_index]["body"][field] = new_value
    except Exception:
        pass

    return {
        "tampered": True,
        "receipt_index": receipt_index,
        "field": field,
        "original_value": original_value,
        "new_value": new_value,
        "receipt_hash": receipt.receipt_hash,
        "message": "Receipt tampered. Run /verify-chain to detect the modification.",
    }


# --- Dashboard HTML (served from separate file for maintainability) ---

def _load_dashboard_html() -> str:
    import pathlib
    p = pathlib.Path(__file__).parent / "dashboard.html"
    return p.read_text()

_DASHBOARD_HTML = _load_dashboard_html()
