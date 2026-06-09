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

import base64
import json
import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator

import httpx

from .anchor import AnchorRecord, AnchorSink, create_anchor_sink
from .evidence_buffer import EvidenceBuffer
from .gateway_service import GatewayService
from .artifact_log import ArtifactLog
from .liveness import LivenessManager, LivenessState
from .store import ReceiptStore, create_store
from .verify import verify_chain, verify_receipt

logger = logging.getLogger("gateway.api")

# Use Google Cloud Logging when running on GCP (structured JSON logs in Cloud Logging console)
try:
    if os.environ.get("GOOGLE_CLOUD_PROJECT"):
        import google.cloud.logging as cloud_logging
        cloud_logging.Client().setup_logging(log_level=logging.INFO)
        logger.info("Google Cloud Logging initialized")
    else:
        raise ImportError("local mode")
except (ImportError, Exception):
    logging.basicConfig(
        level=logging.INFO,
        format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
    )

# Module-level state
_gateway: GatewayService | None = None
_store: ReceiptStore | None = None
_anchor: AnchorSink | None = None
_liveness: LivenessManager | None = None
_artifact_log: ArtifactLog | None = None
_evidence_buffer: EvidenceBuffer | None = None

# Hot path mode: "sync" (default, blocking Firestore) or "async" (non-blocking)
HOT_PATH_MODE = os.environ.get("HOT_PATH_MODE", "sync").lower()


def _get_evidence_buffer() -> EvidenceBuffer | None:
    return _evidence_buffer


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


def _get_artifact_log() -> ArtifactLog:
    global _artifact_log
    if _artifact_log is None:
        gateway = _get_gateway()
        firestore_db = None
        if os.environ.get("FIRESTORE_ENABLED", "").lower() == "true":
            try:
                from google.cloud import firestore
                firestore_db = firestore.Client(project=os.environ.get("GOOGLE_CLOUD_PROJECT"))
            except Exception:
                pass
        _artifact_log = ArtifactLog(tenant=gateway.tenant, firestore_client=firestore_db)
    return _artifact_log


def _get_liveness() -> LivenessManager:
    global _liveness
    if _liveness is None:
        interval = int(os.environ.get("ATTESTATION_INTERVAL", "3600"))
        _liveness = LivenessManager(attestation_interval=interval)
    return _liveness


# --- Input size limits ---

MAX_PARAMETERS_BYTES = 64 * 1024   # 64 KiB
MAX_POLICY_RULES = 100
MAX_RULE_BYTES = 16 * 1024         # 16 KiB per rule
MAX_METADATA_BYTES = 8 * 1024      # 8 KiB for action/resource metadata

import re as _re

_SAFE_IDENTIFIER_RE = _re.compile(r"^[a-zA-Z0-9._/\-]+$")


def _validate_dict_size(v, max_bytes, field_name):
    if v is None:
        return v
    serialized = json.dumps(v)
    if len(serialized.encode("utf-8")) > max_bytes:
        raise ValueError(f"{field_name} exceeds {max_bytes} byte limit")
    return v


# --- Request/Response models ---

class AuthorizeRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=256, description="Unique agent identifier")
    action: str = Field(..., min_length=1, max_length=256, description="Action to authorize")
    resource: str = Field(..., min_length=1, max_length=512, description="Target resource")
    parameters: dict | None = None
    agent_proof: str = Field(..., description="DPoP-style agent identity proof JWT (REQUIRED)")

    @field_validator("agent_id", "action", "resource")
    @classmethod
    def strict_identifier(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be empty or whitespace-only")
        if not _SAFE_IDENTIFIER_RE.match(v):
            raise ValueError(
                "must contain only alphanumeric characters, dots, underscores, slashes, or hyphens"
            )
        return v

    @field_validator("parameters")
    @classmethod
    def check_parameters_size(cls, v):
        return _validate_dict_size(v, MAX_PARAMETERS_BYTES, "parameters")


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
            policy = Policy(
                rules=rules,
                version=stored_policy.get("version", "1"),
                require_resource_registration=bool(stored_policy.get("require_resource_registration", False)),
            )
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

        # Hydrate agent registry from Firestore (survives cold starts)
        try:
            loaded = gateway._registry.load_all()
            if loaded:
                logger.info(f"Hydrated agent registry: {loaded} agents from Firestore")
        except Exception as e:
            logger.warning(f"Agent registry hydration (non-fatal): {e}")

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

    # Startup self-check: verify signing key roundtrip
    try:
        from .startup_check import run_signing_key_self_check, check_chain_kid_consistency
        run_signing_key_self_check()
        await check_chain_kid_consistency(store, gateway.tenant, gateway._kid)
    except Exception as e:
        logger.warning(f"Startup self-check (non-fatal): {e}")

    # Start evidence buffer if hot path mode is async
    global _evidence_buffer
    if HOT_PATH_MODE == "async":
        _evidence_buffer = EvidenceBuffer(store=store)
        _evidence_buffer.start()
        logger.info("Hot path mode: ASYNC (evidence buffer enabled)")
    else:
        logger.info("Hot path mode: SYNC (blocking Firestore writes)")

    # Start Base L2 anchor scheduler if enabled (REST service only)
    anchor_task = None
    if os.environ.get("ANCHOR_TO_BASE", "").lower() == "true":
        import asyncio
        from .anchor_scheduler import anchor_loop
        anchor_task = asyncio.create_task(anchor_loop(gateway, store))
        logger.info("Base L2 anchor scheduler started")
    else:
        logger.info("Base L2 anchoring disabled (set ANCHOR_TO_BASE=true to enable)")

    # Start continuous attestation sweep (runs every attestation_interval)
    liveness_task = None
    liveness_mgr = _get_liveness()
    if os.environ.get("CONTINUOUS_ATTESTATION", "").lower() != "false":
        import asyncio

        async def _liveness_sweep_loop():
            while True:
                await asyncio.sleep(liveness_mgr.attestation_interval)
                try:
                    summary = await liveness_mgr.sweep(gateway._registry, gateway.tenant)
                    if summary["checked"] > 0:
                        logger.info(
                            "Liveness sweep: checked=%d passed=%d failed=%d",
                            summary["checked"], summary["passed"], summary["failed"],
                        )
                        # Persist liveness records
                        for record in liveness_mgr.list_all():
                            try:
                                await store.save_liveness(gateway.tenant, record.agent_id, record.to_dict())
                            except Exception:
                                pass
                except Exception as e:
                    logger.warning(f"Liveness sweep error (non-fatal): {e}")

        liveness_task = asyncio.create_task(_liveness_sweep_loop())
        logger.info(f"Continuous attestation enabled (interval={liveness_mgr.attestation_interval}s)")
    else:
        logger.info("Continuous attestation disabled (set CONTINUOUS_ATTESTATION=true to enable)")

    yield

    if _evidence_buffer:
        await _evidence_buffer.stop()
    if anchor_task:
        anchor_task.cancel()
    if liveness_task:
        liveness_task.cancel()


api_app = FastAPI(
    title="Gate",
    description="Cryptographic governance for AI agents — policy enforcement, signed receipts, tamper-evident audit",
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


_SECURITY_TXT = """\
Contact: mailto:security@blockintelai.com
Expires: 2027-06-01T00:00:00.000Z
Preferred-Languages: en
Canonical: https://agent-auth-gateway-1031148889398.us-central1.run.app/.well-known/security.txt
Policy: https://github.com/4KInc/agent-authorization-gateway/blob/main/SECURITY.md

# Gate is a cryptographic authorization layer for enterprise AI agents.
# Security disclosures should reference the threat model in SECURITY.md.
# We respond to all submissions within 5 business days.
"""


@api_app.get("/.well-known/security.txt", response_class=PlainTextResponse)
async def well_known_security_txt():
    """RFC 9116 security.txt for vulnerability disclosure."""
    return _SECURITY_TXT


@api_app.get("/", include_in_schema=False)
async def root():
    """API landing — redirects to Swagger docs."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse("/docs", status_code=307)


@api_app.get("/health")
async def health():
    gateway = _get_gateway()
    evidence_buf = _get_evidence_buffer()
    result = {
        "status": "healthy",
        "tenant": gateway.tenant,
        "provider": "agent-authorization-gateway",
        "hot_path_mode": HOT_PATH_MODE,
    }
    if evidence_buf is not None:
        result["evidence_buffer"] = evidence_buf.stats
    return result


@api_app.post("/evidence/flush")
async def flush_evidence():
    """Force-drain the evidence buffer to Firestore. No-op in sync mode."""
    evidence_buf = _get_evidence_buffer()
    if evidence_buf is None:
        return {"status": "noop", "reason": "sync mode — no buffer", "mode": HOT_PATH_MODE}
    count = await evidence_buf.flush()
    return {"status": "flushed", "persisted": count, **evidence_buf.stats}


@api_app.post("/authorize", response_model=AuthorizeResponse)
async def authorize(req: AuthorizeRequest):
    """Authorize an agent action. Returns decision + receipt + token.

    SECURITY: agent_proof is REQUIRED. The Gateway verifies the agent's
    DPoP identity proof in the service layer before evaluating policy.
    Calls without proof are rejected with 401 NO_PROOF.
    """
    decision_start = time.time()
    gateway = _get_gateway()
    store = _get_store()
    liveness_mgr = _get_liveness()

    # Lazy liveness check: if the agent has a liveness record and it's stale,
    # check policy to decide whether to deny. This happens BEFORE DPoP verification
    # so that suspended agents are rejected early.
    liveness_record = liveness_mgr.get(req.agent_id)
    if liveness_record and liveness_record.should_deny_authorization():
        raise HTTPException(
            403,
            detail={
                "error": "LIVENESS_" + liveness_record.state.value,
                "message": f"Agent '{req.agent_id}' liveness is {liveness_record.state.value}. "
                           f"Re-verification required ({liveness_record.consecutive_failures} consecutive failures).",
                "liveness_state": liveness_record.state.value,
                "consecutive_failures": liveness_record.consecutive_failures,
                "last_failure_reason": liveness_record.last_failure_reason,
            },
        )

    # DPoP verification happens inside gateway.authorize() — single chokepoint
    try:
        response = gateway.authorize(
            agent_id=req.agent_id,
            action=req.action,
            resource=req.resource,
            parameters=req.parameters,
            agent_proof=req.agent_proof,
        )
    except ValueError as e:
        raise HTTPException(401, str(e))

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

    evidence_buf = _get_evidence_buffer()
    if evidence_buf is not None:
        # HOT PATH: non-blocking enqueue, return immediately
        evidence_buf.enqueue("receipt", gateway.tenant, enriched)
        evidence_buf.enqueue("stats", gateway.tenant, gateway.get_chain_stats())
        evidence_buf.enqueue("rate_limits", gateway.tenant, gateway._policy_engine._rate_counters)
    else:
        # SYNC PATH: blocking Firestore writes (default)
        try:
            await store.save_receipt(gateway.tenant, enriched)
            await store.save_stats(gateway.tenant, gateway.get_chain_stats())
            await store.save_rate_limits(gateway.tenant, gateway._policy_engine._rate_counters)
        except Exception as e:
            logger.exception(f"RECEIPT_PERSIST_FAILED: {e}")
            raise HTTPException(500, "Receipt could not be persisted. Token withheld to prevent authorization without audit trail.")

    # Append receipt to unified artifact log for Merkle anchoring
    try:
        art_log = _get_artifact_log()
        art_log.append(
            artifact_type="receipt",
            artifact_id=response.receipt_hash,
            artifact_hash=response.receipt_hash,
            agent_kid=gateway._kid,
        )
    except Exception as e:
        logger.warning(f"Artifact log append (non-fatal): {e}")

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

    decision_ms = round((time.time() - decision_start) * 1000, 1)
    logger.info(
        "authorize: agent=%s action=%s resource=%s decision=%s latency=%.1fms mode=%s",
        req.agent_id, req.action, req.resource, response.decision, decision_ms, HOT_PATH_MODE,
    )

    resp = AuthorizeResponse(
        decision=response.decision,
        reason_codes=response.reason_codes,
        token=response.token,
        receipt=response.receipt,
        action_digest=response.action_digest,
        receipt_hash=response.receipt_hash,
    )
    from fastapi.responses import JSONResponse as _JR
    json_resp = _JR(content=resp.model_dump())
    json_resp.headers["X-Gate-Decision-Ms"] = str(decision_ms)
    json_resp.headers["X-Gate-Hot-Path"] = HOT_PATH_MODE
    return json_resp


@api_app.post("/authorize/dry-run")
async def authorize_dry_run(req: AuthorizeRequest):
    """Simulate an authorization without creating a receipt or token.

    Requires a valid DPoP proof (same as /authorize). Evaluates the
    policy in read-only mode (rate counters are checked but not
    incremented) and returns what the decision would be, without
    signing a receipt or advancing the chain.
    """
    gateway = _get_gateway()

    # DPoP verification — same as /authorize
    if not req.agent_proof:
        raise HTTPException(401, detail={"error": "NO_PROOF"})
    try:
        from .tokens import compute_action_digest
        action_digest = compute_action_digest(req.agent_id, req.action, req.resource, req.parameters)
        from .identity import verify_agent_proof
        verify_agent_proof(
            proof=req.agent_proof,
            registry=gateway._registry,
            expected_agent_id=req.agent_id,
            expected_action=req.action,
            expected_resource=req.resource,
            expected_action_digest=action_digest,
        )
    except ValueError as e:
        error_code = str(e).split(":")[0] if ":" in str(e) else str(e)
        raise HTTPException(401, detail={"error": error_code})

    result = gateway._policy_engine.evaluate(
        agent_id=req.agent_id,
        action=req.action,
        resource=req.resource,
        parameters=req.parameters,
        dry_run=True,
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
    """Verify a single receipt's integrity, signature, and prev_receipt link.

    Performs bounded chain verification: loads the immediate predecessor
    and checks that prev_receipt matches. Genesis receipts return PASS.
    """
    gateway = _get_gateway()
    store = _get_store()
    public_key = await _resolve_key(req.public_key, req.receipt)

    # Load chain for bounded predecessor check
    chain = None
    try:
        stored_chain = await store.get_chain(gateway.tenant)
        if stored_chain:
            chain = stored_chain
        else:
            chain = gateway.get_receipt_chain()
    except Exception:
        chain = gateway.get_receipt_chain()

    result = verify_receipt(req.receipt, public_key, chain=chain)

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
async def get_chain(
    limit: int = Query(100, ge=1, le=500),
    after_seq: int | None = Query(None, ge=0),
):
    """Get the receipt chain (paginated) for audit/verification.

    Returns at most `limit` receipts. Use `after_seq` to fetch the next page
    (pass the `next_cursor` value from the previous response).
    """
    gateway = _get_gateway()
    store = _get_store()

    # Get all receipts (store handles sorting)
    stored_chain = await store.get_chain(gateway.tenant)
    all_receipts = stored_chain if stored_chain else gateway.get_receipt_chain()

    # Apply cursor-based pagination
    if after_seq is not None:
        all_receipts = [
            r for r in all_receipts
            if int((r.get("body", {}) if isinstance(r, dict) else {}).get("seq", 0) or 0) > after_seq
        ]

    page = all_receipts[:limit]
    has_more = len(all_receipts) > limit

    next_cursor = None
    if has_more and page:
        last = page[-1]
        next_cursor = int((last.get("body", {}) if isinstance(last, dict) else {}).get("seq", 0) or 0)

    return {
        "tenant": gateway.tenant,
        "receipts": page,
        "count": len(page),
        "next_cursor": next_cursor,
        "has_more": has_more,
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
    """Get the gateway's shared signing public key as a JWK.

    Returns exactly ONE key — the shared key loaded from Secret Manager.
    All gateway surfaces (REST, MCP, ADK) use this same key.
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
        "require_resource_registration": gateway.policy.require_resource_registration,
        "rules": [
            {"id": r.id, "type": r.type, "config": r.config}
            for r in gateway.policy.rules
        ],
    }


class UpdatePolicyRequest(BaseModel):
    version: str = Field(default="1", description="Policy version")
    rules: list[dict] = Field(..., description="List of policy rules", max_length=MAX_POLICY_RULES)
    require_resource_registration: bool = False

    @field_validator("rules")
    @classmethod
    def check_rules_size(cls, v):
        for i, rule in enumerate(v):
            _validate_dict_size(rule, MAX_RULE_BYTES, f"rules[{i}]")
        return v


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

    policy = Policy(rules=rules, version=req.version,
                    require_resource_registration=req.require_resource_registration)
    gateway.policy = policy
    gateway._policy_engine = PolicyEngine(policy)

    try:
        await store.save_policy(gateway.tenant, {
            "version": req.version,
            "rules": req.rules,
            "require_resource_registration": req.require_resource_registration,
        })
    except Exception as e:
        logger.warning(f"Policy persistence warning: {e}")

    logger.info(f"Policy updated: {len(rules)} rules, hash={policy.policy_hash()[:24]}")
    return {
        "status": "updated",
        "policy_hash": policy.policy_hash(),
        "rule_count": len(rules),
    }


# --- Natural Language Policy Generation ---


class GeneratePolicyRequest(BaseModel):
    description: str = Field(..., min_length=5, max_length=2000, description="Natural language policy description")


@api_app.post("/policy/generate")
async def generate_policy(req: GeneratePolicyRequest):
    """Generate policy rules from a natural language description using Gemini.

    The CCO types English. Gemini writes the policy rules. The output
    can be fed directly into /policy/simulate to preview the impact
    before applying.
    """
    gateway = _get_gateway()
    current_rules = [
        {"id": r.id, "type": r.type, "config": r.config}
        for r in gateway.policy.rules
        if r.type != "agent_binding"
    ]

    prompt = f"""You are Gate's policy generator. Convert the user's natural language description
into Gate policy rules. Output ONLY a JSON object with no markdown fencing.

Available rule types:
1. "allowlist" — config: {{"allowed_actions": ["read", "query", ...]}}
2. "resource_scope" — config: {{"allowed_resources": [...], "denied_resources": [...]}}
3. "rate_limit" — config: {{"max_actions": <int>, "window_seconds": <int>}}

Current policy for context:
{json.dumps(current_rules, indent=2)}

Output schema:
{{
  "rules": [
    {{"id": "<short-kebab-id>", "type": "<type>", "config": {{...}}}}
  ],
  "explanation": "One sentence explaining what changed vs current policy"
}}

User request: {req.description}"""

    try:
        from google import genai
        client = genai.Client(
            vertexai=True,
            project=os.environ.get("GOOGLE_CLOUD_PROJECT"),
            location="us-central1",
        )
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        raw = response.text.strip()

        # Parse JSON from response (handle markdown fencing)
        import re as _re_gen
        fenced = _re_gen.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, _re_gen.S)
        if fenced:
            parsed = json.loads(fenced.group(1))
        else:
            start = raw.find("{")
            end = raw.rfind("}")
            if start != -1 and end > start:
                parsed = json.loads(raw[start:end + 1])
            else:
                raise ValueError("No JSON object in response")

        rules = parsed.get("rules", [])
        explanation = parsed.get("explanation", "")

        # Filter out agent_binding rules (Gemini may copy them from context)
        rules = [r for r in rules if r.get("type") != "agent_binding"]

        # Validate rule structure
        for r in rules:
            if not r.get("id") or not r.get("type"):
                raise ValueError(f"Generated rule missing id or type: {r}")
            if r["type"] not in ("allowlist", "resource_scope", "rate_limit"):
                raise ValueError(f"Unknown rule type: {r['type']}")

        return {
            "rules": rules,
            "explanation": explanation,
            "model": "gemini-2.5-flash",
            "source": "vertex-ai-model-garden",
            "current_policy_hash": gateway.policy.policy_hash(),
        }
    except Exception as e:
        logger.warning(f"Policy generation failed: {e}")
        raise HTTPException(502, f"Policy generation failed: {e}")


# --- Counterfactual Policy Simulation ---


class SimulatePolicyRequest(BaseModel):
    rules: list[dict] = Field(..., description="Proposed policy rules", max_length=MAX_POLICY_RULES)
    version: str = Field(default="proposed", description="Version label for the proposed policy")
    require_resource_registration: bool = False
    lookback_receipts: int = Field(default=500, ge=1, le=5000, description="Max receipts to replay")

    @field_validator("rules")
    @classmethod
    def check_rules_size(cls, v):
        for i, rule in enumerate(v):
            _validate_dict_size(rule, MAX_RULE_BYTES, f"rules[{i}]")
        return v


@api_app.post("/policy/simulate")
async def simulate_policy(req: SimulatePolicyRequest):
    """Counterfactual policy simulation: replay historical receipts against a proposed policy.

    Returns which decisions would change, which agents are affected,
    and a summary of the net scope impact. Does not modify any state.
    """
    from .policy import Policy, PolicyRule, PolicyEngine

    gateway = _get_gateway()
    store = _get_store()

    # Build the candidate policy engine
    rules = []
    for r in req.rules:
        if not r.get("id") or not r.get("type"):
            raise HTTPException(400, "Each rule must have 'id' and 'type' fields")
        rules.append(PolicyRule(id=r["id"], type=r["type"], config=r.get("config", {})))

    candidate = PolicyEngine(Policy(
        rules=rules, version=req.version,
        require_resource_registration=req.require_resource_registration,
    ))

    # Load historical receipts
    stored_chain = await store.get_chain(gateway.tenant)
    all_receipts = stored_chain if stored_chain else gateway.get_receipt_chain()
    receipts = all_receipts[-req.lookback_receipts:]

    # Replay each receipt against the candidate policy
    flips: list[dict] = []
    affected_agents: set[str] = set()
    unaffected_agents: set[str] = set()
    approve_to_deny = 0
    deny_to_approve = 0

    for r in receipts:
        body = r.get("body", {}) if isinstance(r, dict) else {}
        meta = r.get("_meta", {}) if isinstance(r, dict) else {}
        original_decision = body.get("decision")
        agent_id = meta.get("agent_id", "")
        action = meta.get("action", "")
        resource = meta.get("resource", "")
        parameters = meta.get("parameters")

        if not agent_id or not action or not resource:
            continue

        sim_result = candidate.evaluate(
            agent_id=agent_id, action=action, resource=resource,
            parameters=parameters, dry_run=True,
        )

        if sim_result.decision != original_decision:
            flips.append({
                "seq": body.get("seq"),
                "agent_id": agent_id,
                "action": action,
                "resource": resource,
                "original_decision": original_decision,
                "simulated_decision": sim_result.decision,
                "new_reasons": sim_result.reason_codes,
            })
            affected_agents.add(agent_id)
            if original_decision == "approve" and sim_result.decision == "deny":
                approve_to_deny += 1
            elif original_decision == "deny" and sim_result.decision == "approve":
                deny_to_approve += 1
        else:
            unaffected_agents.add(agent_id)

    # Remove agents that appear in both sets
    unaffected_agents -= affected_agents

    total = len(receipts)
    original_approvals = sum(1 for r in receipts
                            if (r.get("body", {}) if isinstance(r, dict) else {}).get("decision") == "approve")
    simulated_approvals = original_approvals - approve_to_deny + deny_to_approve

    return {
        "total_replayed": total,
        "unchanged": total - len(flips),
        "flipped": len(flips),
        "would_flip": flips[:100],  # cap response size
        "has_more_flips": len(flips) > 100,
        "summary": {
            "approvals_that_become_denials": approve_to_deny,
            "denials_that_become_approvals": deny_to_approve,
            "original_approval_rate": f"{(original_approvals / total * 100):.1f}%" if total else "N/A",
            "simulated_approval_rate": f"{(simulated_approvals / total * 100):.1f}%" if total else "N/A",
            "affected_agents": sorted(affected_agents),
            "unaffected_agents": sorted(unaffected_agents),
        },
        "current_policy_hash": gateway.policy.policy_hash(),
        "proposed_policy_hash": candidate.policy.policy_hash(),
    }


# --- Gemini-powered explanations (Google AI integration) ---

@api_app.get("/policy/explain")
async def explain_policy():
    """Use Gemini to explain the current security policy in plain English.

    Demonstrates Google AI integration: the deterministic policy is
    interpreted by Gemini 2.5 Pro via Vertex AI Model Garden to produce
    a human-readable summary for compliance officers and auditors.
    """
    gateway = _get_gateway()
    policy_data = {
        "version": gateway.policy.version,
        "policy_hash": gateway.policy.policy_hash(),
        "rules": [
            {"id": r.id, "type": r.type, "config": r.config}
            for r in gateway.policy.rules
        ],
    }

    try:
        from google import genai
        client = genai.Client(vertexai=True, project=os.environ.get("GOOGLE_CLOUD_PROJECT"), location="us-central1")
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=f"""You are Gate's policy explainer. Summarize this security policy in plain English
for a Chief Compliance Officer. Be specific about what agents can and cannot do.

Policy JSON:
{json.dumps(policy_data, indent=2)}

Format: 3-5 bullet points, each one sentence. No jargon. Start each bullet with what it means for the business.""",
        )
        explanation = response.text
    except Exception as e:
        logger.warning(f"Gemini policy explanation failed: {e}")
        explanation = "Gemini explanation unavailable. The policy has {} rules covering action allowlists, resource scoping, and rate limits.".format(
            len(gateway.policy.rules)
        )

    return {
        "tenant": gateway.tenant,
        "policy_hash": gateway.policy.policy_hash(),
        "rule_count": len(gateway.policy.rules),
        "explanation": explanation,
        "model": "gemini-2.5-flash",
        "source": "vertex-ai-model-garden",
    }


@api_app.get("/chain/{seq}/explain")
async def explain_receipt(seq: int):
    """Use Gemini to explain a specific authorization decision in plain English.

    Given a receipt sequence number, Gemini reads the receipt and its
    audit report (if available) and produces a human-readable explanation
    of what happened and why.
    """
    gateway = _get_gateway()
    store = _get_store()

    stored_chain = await store.get_chain(gateway.tenant)
    receipt = None
    for r in (stored_chain or []):
        if int(r.get("body", {}).get("seq", 0)) == seq:
            receipt = r
            break

    if not receipt:
        raise HTTPException(404, f"Receipt seq={seq} not found")

    body = receipt.get("body", {})
    meta = receipt.get("_meta", {})

    try:
        from google import genai
        client = genai.Client(vertexai=True, project=os.environ.get("GOOGLE_CLOUD_PROJECT"), location="us-central1")
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=f"""You are Gate's receipt explainer. Explain this authorization decision in plain English
for a security analyst reviewing an audit trail.

Receipt:
- Sequence: {body.get('seq')}
- Decision: {body.get('decision')}
- Reasons: {body.get('reasons', [])}
- Agent: {meta.get('agent_id', 'unknown')}
- Action: {meta.get('action', 'unknown')}
- Resource: {meta.get('resource', 'unknown')}
- Timestamp: {body.get('ts')}
- Policy version: {body.get('policy_version', '')[:24]}...

In 2-3 sentences: What did the agent try to do? Was it allowed or denied? Why?""",
        )
        explanation = response.text
    except Exception as e:
        logger.warning(f"Gemini receipt explanation failed: {e}")
        explanation = f"Agent '{meta.get('agent_id')}' attempted '{meta.get('action')}' on '{meta.get('resource')}'. Decision: {body.get('decision')}. Reasons: {', '.join(body.get('reasons', []) or ['policy approved'])}."

    return {
        "seq": seq,
        "decision": body.get("decision"),
        "agent_id": meta.get("agent_id"),
        "action": meta.get("action"),
        "resource": meta.get("resource"),
        "explanation": explanation,
        "model": "gemini-2.5-flash",
        "source": "vertex-ai-model-garden",
    }


# --- Agent Registration with Proof of Possession ---

from .identity import RegistrationChallengeCache, verify_registration_proof

_challenge_cache = RegistrationChallengeCache()


class AgentChallengeRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=256)


@api_app.post("/agents/register-challenge")
async def register_challenge(req: AgentChallengeRequest, request: Request):
    """Get a registration challenge nonce (step 1 of 2).

    Rate-limited to 10 challenges per minute per IP.
    Global capacity cap of 10,000 active challenges.
    """
    client_ip = request.client.host if request.client else "unknown"

    if not _challenge_cache.check_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail={"error": "CHALLENGE_RATE_LIMIT_EXCEEDED", "retry_after_seconds": 60},
        )

    if not _challenge_cache.check_capacity():
        raise HTTPException(
            status_code=503,
            detail={"error": "CHALLENGE_CAPACITY_EXCEEDED", "retry_after_seconds": 60},
        )

    gateway = _get_gateway()
    return _challenge_cache.issue(gateway.tenant, req.agent_id)


class AgentRegisterProof(BaseModel):
    nonce: str
    challenge_id: str
    signature: str
    iat: int


class AgentRegisterRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=256)
    public_key: dict = Field(..., description="Agent's Ed25519 public key as JWK")
    proof: AgentRegisterProof = Field(..., description="Proof of possession")
    agent_card_url: str | None = Field(None, description="Optional A2A agent card URL for existence verification")
    live_challenge_url: str | None = Field(None, description="Optional callback URL for signed liveness challenge")


async def _verify_agent_card(agent_card_url: str | None, declared_jwk: dict) -> dict:
    """Fetch the agent's A2A card and verify the declared public key matches."""
    if not agent_card_url:
        return {"status": "skipped", "reason": "no agent_card_url provided"}
    try:
        headers = {}
        # Use Google identity token for Cloud Run service-to-service auth
        try:
            from google.oauth2 import id_token as google_id_token
            from google.auth.transport.requests import Request
            from urllib.parse import urlparse
            # Cloud Run expects audience = base URL (no path)
            parsed = urlparse(agent_card_url)
            audience = f"{parsed.scheme}://{parsed.netloc}"
            token = google_id_token.fetch_id_token(Request(), audience)
            headers["Authorization"] = f"Bearer {token}"
        except Exception:
            pass  # Fall back to unauthenticated if not on GCP
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(agent_card_url, headers=headers)
            if resp.status_code != 200:
                return {"status": "failed", "reason": f"card URL returned {resp.status_code}"}
            card = resp.json()
    except Exception as e:
        return {"status": "failed", "reason": f"fetch error: {e}"}

    card_key = card.get("signing_key") or card.get("public_key") or card.get("authentication", {}).get("signing_key")
    if not card_key or not isinstance(card_key, dict):
        return {"status": "failed", "reason": "card does not declare signing_key"}

    if declared_jwk.get("x") != card_key.get("x"):
        return {"status": "failed", "reason": "card public key does not match registered key"}

    return {"status": "verified", "reason": "card public key matches registered key"}


async def _verify_agent_liveness(
    live_challenge_url: str | None,
    declared_jwk: dict,
    agent_id: str,
    tenant_id: str,
) -> dict:
    """POST a fresh nonce to the agent's callback URL and verify it signs
    the challenge with the private key matching the registered public key."""
    import secrets as _secrets
    if not live_challenge_url:
        return {"status": "skipped", "reason": "no live_challenge_url provided", "challenge_id": None}

    nonce = base64.urlsafe_b64encode(_secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge_id = base64.urlsafe_b64encode(_secrets.token_bytes(16)).rstrip(b"=").decode()
    iat = int(time.time())

    challenge_payload = {
        "v": "1",
        "type": "agent_liveness_challenge",
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "nonce": nonce,
        "challenge_id": challenge_id,
        "iat": iat,
    }

    try:
        headers = {}
        try:
            from google.oauth2 import id_token as google_id_token
            from google.auth.transport.requests import Request
            from urllib.parse import urlparse
            parsed = urlparse(live_challenge_url)
            audience = f"{parsed.scheme}://{parsed.netloc}"
            token = google_id_token.fetch_id_token(Request(), audience)
            headers["Authorization"] = f"Bearer {token}"
        except Exception:
            pass
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(live_challenge_url, json=challenge_payload, headers=headers)
            if resp.status_code != 200:
                return {"status": "failed", "reason": f"callback returned {resp.status_code}", "challenge_id": challenge_id}
            response_data = resp.json()
    except httpx.TimeoutException:
        return {"status": "failed", "reason": "callback timeout (>5s)", "challenge_id": challenge_id}
    except Exception as e:
        return {"status": "failed", "reason": f"callback error: {type(e).__name__}: {e}", "challenge_id": challenge_id}

    signature_b64 = response_data.get("signature")
    if not signature_b64:
        return {"status": "failed", "reason": "callback response missing 'signature' field", "challenge_id": challenge_id}

    # Reconstruct canonical bytes the agent should have signed
    canonical_bytes = json.dumps(challenge_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    try:
        sig_padded = signature_b64 + "=" * (-len(signature_b64) % 4)
        signature = base64.urlsafe_b64decode(sig_padded)
    except Exception as e:
        return {"status": "failed", "reason": f"signature decode error: {e}", "challenge_id": challenge_id}

    x_b64 = declared_jwk.get("x", "")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        x_padded = x_b64 + "=" * (-len(x_b64) % 4)
        pub_bytes = base64.urlsafe_b64decode(x_padded)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(signature, canonical_bytes)
        return {"status": "verified", "reason": "signed challenge response verified", "challenge_id": challenge_id}
    except InvalidSignature:
        return {"status": "failed", "reason": "signature does not verify against the registered public key", "challenge_id": challenge_id}
    except Exception as e:
        return {"status": "failed", "reason": f"verification error: {e}", "challenge_id": challenge_id}


@api_app.post("/agents/register")
async def register_agent(req: AgentRegisterRequest):
    """Register with proof of possession (step 2 of 2). Replace semantics.

    Optionally verifies the agent's A2A card URL if provided. Verification
    failure does NOT block registration — the status is recorded.
    """
    gateway = _get_gateway()
    valid, err = verify_registration_proof(
        public_key_jwk=req.public_key,
        proof=req.proof.model_dump(),
        tenant_id=gateway.tenant,
        agent_id=req.agent_id,
        challenge_cache=_challenge_cache,
    )
    if not valid:
        status = 401 if err == "INVALID_PROOF_SIGNATURE" else 400
        raise HTTPException(status, detail=err)

    card_result = await _verify_agent_card(req.agent_card_url, req.public_key)
    live_result = await _verify_agent_liveness(
        req.live_challenge_url, req.public_key, req.agent_id, gateway.tenant,
    )

    try:
        agent = gateway._registry.register(
            req.agent_id, req.public_key,
            live_challenge_url=req.live_challenge_url,
        )
        from datetime import datetime, timezone

        # Seed the liveness record for continuous attestation
        liveness_mgr = _get_liveness()
        liveness_record = liveness_mgr.get_or_create(req.agent_id, req.live_challenge_url)
        if live_result["status"] == "verified":
            liveness_record.record_success()
        elif req.live_challenge_url:
            liveness_record.record_failure(live_result.get("reason", "initial check failed"))

        # Persist liveness state
        store = _get_store()
        try:
            await store.save_liveness(gateway.tenant, req.agent_id, liveness_record.to_dict())
        except Exception:
            pass

        return {
            "status": "registered",
            "agent_id": agent.agent_id,
            "kid": agent.kid,
            "proof_of_possession_at_registration": True,
            "agent_card_url": req.agent_card_url,
            "agent_card_verification": card_result["status"],
            "agent_card_verification_reason": card_result.get("reason"),
            "live_challenge_url": req.live_challenge_url,
            "live_challenge_verification": live_result["status"],
            "live_challenge_verification_reason": live_result.get("reason"),
            "live_challenge_verified_at": (
                datetime.now(timezone.utc).isoformat()
                if live_result["status"] == "verified" else None
            ),
            "liveness_state": liveness_record.state.value,
        }
    except Exception as e:
        raise HTTPException(400, f"Registration failed: {e}")


@api_app.delete("/agents/{agent_id}")
async def delete_agent(agent_id: str):
    """Delete an agent's registration and liveness record."""
    try:
        _get_gateway()._registry.revoke(agent_id)
        _get_liveness().remove(agent_id)
        return {"status": "deleted", "agent_id": agent_id}
    except ValueError as e:
        raise HTTPException(404, str(e))


class AgentRegisterByUrlRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=256)
    agent_card_url: str = Field(..., description="URL to the agent's A2A card JSON")
    live_challenge_url: str = Field(..., description="URL for liveness challenges")


@api_app.post("/agents/register-by-url")
async def register_agent_by_url(req: AgentRegisterByUrlRequest):
    """Register an agent by its card URL + liveness URL.

    The gateway fetches the public key from the agent's card, sends a
    liveness challenge, and uses the signed response as proof of possession.
    No private key needs to leave the agent.
    """
    gateway = _get_gateway()
    store = _get_store()

    # Step 1: Fetch agent card to get public key
    try:
        headers = {}
        try:
            from google.oauth2 import id_token as google_id_token
            from google.auth.transport.requests import Request
            from urllib.parse import urlparse
            parsed = urlparse(req.agent_card_url)
            audience = f"{parsed.scheme}://{parsed.netloc}"
            token = google_id_token.fetch_id_token(Request(), audience)
            headers["Authorization"] = f"Bearer {token}"
        except Exception:
            pass
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(req.agent_card_url, headers=headers)
            if resp.status_code != 200:
                raise HTTPException(400, f"Could not fetch agent card: HTTP {resp.status_code}")
            card = resp.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Could not fetch agent card: {e}")

    card_key = card.get("signing_key") or card.get("public_key") or card.get("authentication", {}).get("signing_key")
    if not card_key or not isinstance(card_key, dict) or not card_key.get("x"):
        raise HTTPException(400, "Agent card does not contain a signing_key with x value")

    public_key_jwk = {"kty": "OKP", "crv": "Ed25519", "x": card_key["x"]}

    # Step 2: Send liveness challenge — the agent signs it, proving it controls the key
    live_result = await _verify_agent_liveness(
        req.live_challenge_url, public_key_jwk, req.agent_id, gateway.tenant,
    )

    if live_result["status"] != "verified":
        raise HTTPException(
            400,
            f"Liveness challenge failed: {live_result.get('reason', 'unknown')}. "
            f"The agent must sign the challenge with the private key matching the card's public key.",
        )

    # Step 3: Register (liveness = proof of possession)
    try:
        agent = gateway._registry.register(
            req.agent_id, public_key_jwk,
            live_challenge_url=req.live_challenge_url,
        )

        # Seed liveness record
        liveness_mgr = _get_liveness()
        liveness_record = liveness_mgr.get_or_create(req.agent_id, req.live_challenge_url)
        liveness_record.record_success()
        try:
            await store.save_liveness(gateway.tenant, req.agent_id, liveness_record.to_dict())
        except Exception:
            pass

        # Persist verification results
        gateway._registry.update_verification(
            agent.agent_id,
            card_verification="verified",
            card_reason="Card public key matches registered key",
            live_verification="verified",
            live_reason="Signed liveness challenge verified",
            card_url=req.agent_card_url,
        )

        from datetime import datetime, timezone
        return {
            "status": "registered",
            "agent_id": agent.agent_id,
            "kid": agent.kid,
            "proof_of_possession_at_registration": True,
            "agent_card_url": req.agent_card_url,
            "agent_card_verification": "verified",
            "agent_card_verification_reason": "Card public key matches registered key",
            "live_challenge_url": req.live_challenge_url,
            "live_challenge_verification": "verified",
            "live_challenge_verification_reason": "Signed liveness challenge verified",
            "live_challenge_verified_at": datetime.now(timezone.utc).isoformat(),
            "liveness_state": liveness_record.state.value,
        }
    except Exception as e:
        raise HTTPException(400, f"Registration failed: {e}")


@api_app.get("/agents")
async def list_agents(include_revoked: bool = False):
    """List all registered agents with liveness state."""
    agents = _get_gateway()._registry.list_agents()
    liveness_mgr = _get_liveness()

    # Enrich all agents with verification data from Firestore
    registry = _get_gateway()._registry
    firestore_data: dict[str, dict] = {}
    if registry._db:
        try:
            col = registry._db.collection("tenants").document(registry._tenant).collection("agent_registry")
            for doc in col.stream():
                data = doc.to_dict()
                firestore_data[data.get("agent_id", doc.id)] = data
        except Exception:
            pass

    verification_fields = [
        "agent_card_verification", "agent_card_verification_reason",
        "live_challenge_verification", "live_challenge_verification_reason",
        "agent_card_url",
    ]
    for agent in agents:
        fs = firestore_data.get(agent["agent_id"], {})
        for f in verification_fields:
            if f in fs:
                agent[f] = fs[f]

    # Include revoked agents from Firestore
    if include_revoked:
        active_ids = {a["agent_id"] for a in agents}
        for aid, data in firestore_data.items():
            if aid not in active_ids:
                entry = {
                    "agent_id": aid,
                    "kid": data.get("kid", ""),
                    "registered_at": data.get("registered_at", 0),
                    "live_challenge_url": data.get("live_challenge_url"),
                    "status": data.get("status", "revoked"),
                    "revoked_at": data.get("revoked_at"),
                }
                for f in verification_fields:
                    if f in data:
                        entry[f] = data[f]
                agents.append(entry)

    for agent in agents:
        if "status" not in agent:
            agent["status"] = "active"
        record = liveness_mgr.get(agent["agent_id"])
        if record:
            agent["liveness_state"] = record.state.value
            agent["liveness_verified_at"] = record.to_dict()["liveness_verified_at"]
        else:
            agent["liveness_state"] = "UNKNOWN"
            agent["liveness_verified_at"] = None
    return {"agents": agents}


# --- Continuous Attestation (Liveness) endpoints ---

@api_app.get("/agents/liveness")
async def list_agent_liveness():
    """Get liveness state for all registered agents."""
    liveness_mgr = _get_liveness()
    records = liveness_mgr.list_all()
    summary = {
        "LIVE": sum(1 for r in records if r.state == LivenessState.LIVE),
        "WARNING": sum(1 for r in records if r.state == LivenessState.WARNING),
        "STALE": sum(1 for r in records if r.state == LivenessState.STALE),
        "SUSPENDED": sum(1 for r in records if r.state == LivenessState.SUSPENDED),
        "UNKNOWN": sum(1 for r in records if r.state == LivenessState.UNKNOWN),
    }
    return {
        "agents": [r.to_dict() for r in records],
        "summary": summary,
        "attestation_interval": liveness_mgr.attestation_interval,
    }


@api_app.get("/agents/{agent_id}/liveness")
async def get_agent_liveness(agent_id: str):
    """Get detailed liveness state for a specific agent."""
    liveness_mgr = _get_liveness()
    record = liveness_mgr.get(agent_id)
    if record is None:
        raise HTTPException(404, f"No liveness record for agent '{agent_id}'")
    return record.to_dict()


@api_app.post("/agents/{agent_id}/liveness/check")
async def check_agent_liveness(agent_id: str):
    """Trigger an immediate liveness re-challenge for a specific agent.

    Useful for manual verification or after incident response.
    Updates the agent's liveness state based on the result.
    """
    gateway = _get_gateway()
    store = _get_store()
    liveness_mgr = _get_liveness()

    agent = gateway._registry.get(agent_id)
    if agent is None:
        raise HTTPException(404, f"Agent '{agent_id}' is not registered")

    record = liveness_mgr.get(agent_id)
    if record is None:
        # Try to recover live_challenge_url from Firestore
        live_url = None
        registry = gateway._registry
        if registry._db:
            try:
                doc = registry._db.collection("tenants").document(registry._tenant).collection("agent_registry").document(agent_id).get()
                if doc.exists:
                    live_url = doc.to_dict().get("live_challenge_url")
            except Exception:
                pass
        if live_url:
            record = liveness_mgr.get_or_create(agent_id, live_url)
        else:
            raise HTTPException(404, f"No liveness record for agent '{agent_id}'")

    if not record.live_challenge_url:
        return {
            "status": "skipped",
            "reason": "Agent has no live_challenge_url configured",
            "liveness_state": record.state.value,
        }

    pub_bytes = agent.public_key.public_bytes_raw()
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode(),
    }

    record = await liveness_mgr.check_agent(agent_id, jwk, gateway.tenant)

    # Persist updated liveness state
    try:
        await store.save_liveness(gateway.tenant, agent_id, record.to_dict())
    except Exception:
        pass

    return {
        "status": "checked",
        "liveness_state": record.state.value,
        "consecutive_failures": record.consecutive_failures,
        "total_checks": record.total_checks,
        "liveness_verified_at": record.to_dict()["liveness_verified_at"],
        "last_failure_reason": record.last_failure_reason,
    }


@api_app.post("/agents/liveness/sweep")
async def trigger_liveness_sweep():
    """Trigger an immediate liveness sweep of all agents.

    Re-challenges every agent whose liveness is stale (older than
    the attestation interval). Returns a summary of results.
    """
    gateway = _get_gateway()
    store = _get_store()
    liveness_mgr = _get_liveness()

    summary = await liveness_mgr.sweep(gateway._registry, gateway.tenant)

    # Persist all updated records
    for record in liveness_mgr.list_all():
        try:
            await store.save_liveness(gateway.tenant, record.agent_id, record.to_dict())
        except Exception:
            pass

    return {
        "status": "completed",
        **summary,
        "attestation_interval": liveness_mgr.attestation_interval,
    }


# --- Action endpoints ---

from .actions import ActionConflict, ActionRegistry, RiskLevel


def _get_action_registry():
    from .actions import ActionRegistry
    gateway = _get_gateway()
    reg = getattr(gateway, "_action_registry", None)
    if reg is None:
        firestore_db = None
        if os.environ.get("FIRESTORE_ENABLED", "").lower() == "true":
            try:
                from google.cloud import firestore
                firestore_db = firestore.Client(project=os.environ.get("GOOGLE_CLOUD_PROJECT"))
            except Exception:
                pass
        gateway._action_registry = ActionRegistry(tenant_id=gateway.tenant, firestore_client=firestore_db)
        reg = gateway._action_registry
    return reg


class ActionRegisterRequest(BaseModel):
    action_id: str = Field(..., min_length=1, max_length=256)
    display_name: str = Field(..., min_length=1, max_length=256)
    description: str = ""
    risk_level: RiskLevel = Field(..., description="Risk classification")
    resource_type: ResourceType = Field(..., description="Resource type this action applies to")
    requires_human_approval: bool = False
    metadata: dict | None = None

    @field_validator("metadata")
    @classmethod
    def check_metadata_size(cls, v):
        return _validate_dict_size(v, MAX_METADATA_BYTES, "metadata")


class ActionUpdateRequest(BaseModel):
    display_name: str | None = Field(None, max_length=256)
    description: str | None = Field(None, max_length=2048)
    risk_level: str | None = None
    requires_human_approval: bool | None = None
    metadata: dict | None = None

    @field_validator("metadata")
    @classmethod
    def check_metadata_size(cls, v):
        return _validate_dict_size(v, MAX_METADATA_BYTES, "metadata")


@api_app.post("/actions/register")
async def register_action(req: ActionRegisterRequest, request: Request):
    """Register an action in the tenant's action registry."""
    caller = _get_caller_identity_safe(request)
    registry = _get_action_registry()
    try:
        result = registry.register(
            action_id=req.action_id,
            display_name=req.display_name,
            resource_type=req.resource_type.value,
            description=req.description,
            risk_level=req.risk_level.value,
            requires_human_approval=req.requires_human_approval,
            registered_by=caller or "anonymous",
            metadata=req.metadata,
        )
        return {"status": "registered", **{k: result[k] for k in ("action_id", "resource_type", "display_name", "risk_level", "version", "registered_at")}}
    except ActionConflict as e:
        raise HTTPException(409, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


@api_app.get("/actions")
async def list_actions(
    resource_type: str | None = None,
    include_revoked: bool = False,
    limit: int = 100,
):
    """List registered actions, optionally filtered by resource_type."""
    registry = _get_action_registry()
    actions = registry.list_all(include_revoked=include_revoked, limit=limit, resource_type=resource_type)
    return {"actions": actions, "count": len(actions)}


@api_app.get("/actions/{action_id:path}")
async def get_action(action_id: str, resource_type: str | None = None, include_revoked: bool = False):
    """Get a specific action by ID, optionally scoped to a resource_type."""
    registry = _get_action_registry()
    action = registry.get(action_id, resource_type=resource_type, include_revoked=include_revoked)
    if action is None:
        raise HTTPException(404, f"Action '{action_id}' not found")
    return action


@api_app.delete("/actions/{action_id:path}")
async def revoke_action(action_id: str):
    """Revoke an action."""
    registry = _get_action_registry()
    try:
        result = registry.revoke(action_id)
        return {"status": "revoked", "action_id": action_id}
    except ValueError as e:
        raise HTTPException(404, str(e))


@api_app.patch("/actions/{action_id:path}")
async def update_action(action_id: str, updates: ActionUpdateRequest, request: Request):
    """Update action metadata."""
    registry = _get_action_registry()
    try:
        result = registry.update(action_id, updates.model_dump(exclude_none=True))
        return result
    except ValueError as e:
        raise HTTPException(404, str(e))


def _get_caller_identity_safe(request) -> str:
    for header in ["x-goog-authenticated-user-email", "x-forwarded-user"]:
        val = request.headers.get(header, "")
        if val:
            return val.removeprefix("accounts.google.com:")
    return ""


def _get_caller_identity(request) -> str:
    """Extract the authenticated caller identity from Cloud Run headers."""
    for header in ["x-goog-authenticated-user-email", "x-forwarded-user"]:
        val = request.headers.get(header, "")
        if val:
            return val.removeprefix("accounts.google.com:")
    return ""


# --- Resource endpoints ---

from enum import Enum

class ResourceType(str, Enum):
    DB = "db"
    API = "api"
    STORAGE = "storage"
    QUEUE = "queue"
    FUNCTION = "function"


class ResourceRegisterRequest(BaseModel):
    resource_id: str = Field(..., min_length=1, max_length=256)
    display_name: str = Field(..., min_length=1, max_length=256)
    description: str = ""
    resource_type: ResourceType = Field(..., description="Resource type (e.g., db)")
    owner: str = ""
    metadata: dict | None = None
    reachability_url: str | None = Field(None, description="Optional URL for reachability verification")

    @field_validator("metadata")
    @classmethod
    def check_metadata_size(cls, v):
        return _validate_dict_size(v, MAX_METADATA_BYTES, "metadata")


class ResourceUpdateRequest(BaseModel):
    display_name: str | None = None
    description: str | None = None
    resource_type: ResourceType | None = None
    owner: str | None = None
    metadata: dict | None = None

    @field_validator("metadata")
    @classmethod
    def check_metadata_size(cls, v):
        return _validate_dict_size(v, MAX_METADATA_BYTES, "metadata")


def _get_resource_registry():
    from .resources import ResourceRegistry
    gateway = _get_gateway()
    reg = getattr(gateway, "_resource_registry", None)
    # Upgrade to Firestore-backed registry if not already
    if reg is None or (reg._db is None and os.environ.get("FIRESTORE_ENABLED", "").lower() == "true"):
        firestore_db = None
        if os.environ.get("FIRESTORE_ENABLED", "").lower() == "true":
            try:
                from google.cloud import firestore
                firestore_db = firestore.Client(project=os.environ.get("GOOGLE_CLOUD_PROJECT"))
            except Exception:
                pass
        gateway._resource_registry = ResourceRegistry(
            tenant_id=gateway.tenant, firestore_client=firestore_db,
        )
    return gateway._resource_registry


async def _verify_resource(
    resource_type: str,
    reachability_url: str | None,
    metadata: dict | None,
) -> dict:
    """Dispatch to the type-specific resource verifier.

    Each resource type (db, api, storage, queue, function) has its own
    verifier that knows how to confirm the resource exists. Falls back
    to a generic URL probe if no type-specific verifier is registered.
    """
    from .verification import get_verifier, VerificationResult

    verifier = get_verifier(resource_type)
    if verifier:
        result = await verifier.verify(reachability_url, metadata)
        return result.to_dict()

    # Fallback: generic URL probe for unknown types
    if reachability_url:
        from .verification._http import probe_url
        result = await probe_url(reachability_url, resource_type)
        return result.to_dict()

    return {"status": "skipped", "reason": f"No verifier for type '{resource_type}' and no reachability_url"}


@api_app.post("/resources/register")
async def register_resource(req: ResourceRegisterRequest, request: Request):
    """Register a resource with type-specific existence verification.

    Each resource type (db, api, storage, queue, function) has its own
    verifier. Verification is non-blocking — a failed or skipped verification
    does not prevent registration, but the result is recorded.
    """
    from .resources import ResourceConflict
    caller = _get_caller_identity(request)
    registry = _get_resource_registry()

    # Run verification with full metadata (including ephemeral credentials)
    verification = await _verify_resource(
        resource_type=req.resource_type.value,
        reachability_url=req.reachability_url,
        metadata=req.metadata,
    )

    # Strip verification_credentials before persisting — never store secrets
    persist_metadata = dict(req.metadata) if req.metadata else {}
    persist_metadata.pop("verification_credentials", None)

    try:
        result = registry.register(
            resource_id=req.resource_id,
            display_name=req.display_name,
            description=req.description,
            resource_type=req.resource_type,
            owner=req.owner,
            metadata=persist_metadata or None,
            registered_by=caller or "anonymous",
        )
        # Persist verification result as top-level fields on the resource doc
        registry.update_verification(
            req.resource_id,
            verification["status"],
            verification.get("reason"),
        )
        return {
            "status": "registered",
            "resource_id": result["resource_id"],
            "resource_type": req.resource_type.value,
            "display_name": result["display_name"],
            "version": result["version"],
            "registered_at": result["registered_at"],
            "reachability_url": req.reachability_url,
            "verification": verification["status"],
            "verification_reason": verification.get("reason"),
            "verification_details": verification.get("details"),
        }
    except ResourceConflict as e:
        raise HTTPException(409, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


@api_app.get("/resources/types")
async def list_resource_types():
    """List all supported resource types and their verification metadata."""
    from .verification import get_verifier, list_resource_types as _list_types
    types = []
    for rt in _list_types():
        v = get_verifier(rt)
        types.append({
            "type": rt,
            "required_metadata_fields": v.required_metadata_fields if v else [],
        })
    return {"resource_types": types, "count": len(types)}


@api_app.get("/resources")
async def list_resources(
    include_revoked: bool = False,
    limit: int = 100,
    cursor: str | None = None,
):
    """List registered resources (paginated)."""
    registry = _get_resource_registry()
    resources, next_cursor = registry.list_all(
        include_revoked=include_revoked, limit=limit, cursor=cursor,
    )
    return {"resources": resources, "next_cursor": next_cursor, "count": len(resources)}


@api_app.get("/resources/{resource_id:path}")
async def get_resource(resource_id: str):
    """Get a single resource by ID."""
    registry = _get_resource_registry()
    result = registry.get(resource_id)
    if not result:
        raise HTTPException(404, f"Resource '{resource_id}' not found")
    return result


@api_app.delete("/resources/{resource_id:path}")
async def revoke_resource(resource_id: str, request: Request):
    """Revoke a resource registration."""
    caller = _get_caller_identity(request)
    registry = _get_resource_registry()
    try:
        result = registry.revoke(resource_id, revoked_by=caller or "anonymous")
        return {"status": "revoked", "resource_id": resource_id}
    except ValueError as e:
        raise HTTPException(404, str(e))


@api_app.patch("/resources/{resource_id:path}")
async def update_resource(resource_id: str, req: ResourceUpdateRequest, request: Request):
    """Update resource metadata."""
    caller = _get_caller_identity(request)
    registry = _get_resource_registry()
    try:
        result = registry.update_metadata(
            resource_id=resource_id,
            updated_by=caller or "anonymous",
            display_name=req.display_name,
            description=req.description,
            resource_type=req.resource_type,
            owner=req.owner,
            metadata=req.metadata,
        )
        return result
    except ValueError as e:
        raise HTTPException(404 if "not found" in str(e).lower() else 400, str(e))


@api_app.get("/anchors")
async def get_anchors():
    """Get all on-chain anchor records (Base L2 mainnet).

    Anonymous endpoint — anchoring is public by design.
    Each record includes the BaseScan URL for independent verification.
    """
    gateway = _get_gateway()
    store = _get_store()
    records = await store.list_anchor_records(gateway.tenant)
    # Also include legacy local anchors
    anchor = _get_anchor()
    local_anchors = await anchor.get_anchors(gateway.tenant)
    return {
        "tenant": gateway.tenant,
        "on_chain_anchors": records,
        "local_anchors": local_anchors,
        "on_chain_count": len(records),
    }


@api_app.post("/anchors/trigger")
async def trigger_anchor():
    """On-demand Merkle anchoring to Base L2.

    Computes a unified Merkle root over all artifacts since the last
    anchor and submits it to Base L2. Use this during demos to anchor
    immediately instead of waiting for the scheduled threshold.

    Returns the anchor result with tx hash and BaseScan URL.
    """
    import asyncio
    from .artifact_log import ArtifactLog
    from .merkle import compute_unified_root

    gateway = _get_gateway()
    store = _get_store()

    firestore_db = None
    if os.environ.get("FIRESTORE_ENABLED", "").lower() == "true":
        try:
            from google.cloud import firestore
            firestore_db = firestore.Client(project=os.environ.get("GOOGLE_CLOUD_PROJECT"))
        except Exception:
            pass

    art_log = ArtifactLog(tenant=gateway.tenant, firestore_client=firestore_db)

    # Find last anchor seq
    last_anchor_seq = 0
    try:
        anchor_records = await store.list_anchor_records(gateway.tenant)
        if anchor_records:
            last_range = anchor_records[0].get("artifact_seq_range")
            if last_range:
                last_anchor_seq = last_range[1]
    except Exception:
        pass

    current_seq = art_log.head_seq
    if current_seq <= last_anchor_seq:
        return {"status": "skipped", "reason": "No new artifacts since last anchor",
                "last_anchor_seq": last_anchor_seq, "current_seq": current_seq}

    hashes = art_log.get_all_hashes_since(last_anchor_seq)
    if not hashes:
        return {"status": "skipped", "reason": "No artifact hashes found"}

    hex_hashes = [h.removeprefix("sha256:") for h in hashes]
    unified_root = compute_unified_root(hex_hashes)

    try:
        from .base_anchor import anchor_root
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, anchor_root, unified_root, current_seq)

        from datetime import datetime, timezone
        record = {
            **result.to_dict(),
            "anchor_type": "unified",
            "artifact_count": len(hashes),
            "artifact_seq_range": [last_anchor_seq + 1, current_seq],
            "anchored_at": datetime.now(timezone.utc).isoformat(),
        }
        await store.save_anchor_record(gateway.tenant, record)

        return {
            "status": "anchored",
            "tx_hash": result.tx_hash,
            "block_number": result.block_number,
            "basescan_url": f"https://basescan.org/tx/{result.tx_hash}",
            "merkle_root": unified_root,
            "artifact_count": len(hashes),
            "artifact_seq_range": [last_anchor_seq + 1, current_seq],
        }
    except Exception as e:
        raise HTTPException(502, f"Base L2 anchor failed: {e}")


@api_app.get("/anchors/verify/{tx_hash}")
async def verify_anchor(tx_hash: str):
    """Independently verify an on-chain anchor by fetching the tx from Base.

    Confirms the calldata of the Base transaction matches the stored
    Merkle root. Anyone can replicate this check with a public Base RPC.
    """
    gateway = _get_gateway()
    store = _get_store()

    # Look up the stored record
    record = await store.get_anchor_record(gateway.tenant, tx_hash)
    expected_root = record.get("merkle_root") if record else None

    try:
        from .base_anchor import verify_anchor_on_chain
        result = verify_anchor_on_chain(tx_hash, expected_root)
        return result
    except Exception as e:
        raise HTTPException(502, f"Could not verify anchor on Base: {e}")


@api_app.get("/artifacts/log")
async def get_artifact_log(
    after_seq: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
):
    """Get the unified artifact log — all signed artifacts in chronological order.

    This log covers receipts, audit reports, policy proposals, incident reports,
    and isolation records. It is the input to the unified Merkle tree that gets
    anchored to Base L2.
    """
    art_log = _get_artifact_log()
    entries = art_log.get_entries_since(after_seq, limit=limit)
    return {
        "entries": [e.to_dict() for e in entries],
        "count": len(entries),
        "head_seq": art_log.head_seq,
        "has_more": len(entries) == limit,
    }


@api_app.get("/artifacts/proof/{artifact_hash}")
async def get_artifact_inclusion_proof(artifact_hash: str):
    """Get a Merkle inclusion proof for a specific artifact.

    The proof allows a verifier to confirm that the artifact was included
    in a batch that was anchored to Base L2. The verifier recomputes
    the root from the leaf using the proof path and compares it to the
    on-chain root.
    """
    from .merkle import compute_inclusion_proof

    art_log = _get_artifact_log()
    # Find the artifact in the log
    # Get all entries and search for the matching hash
    entries = art_log.get_entries_since(0, limit=10000)
    all_hashes_hex = [e.artifact_hash.removeprefix("sha256:") for e in entries]
    target_hex = artifact_hash.removeprefix("sha256:")

    if target_hex not in all_hashes_hex:
        raise HTTPException(404, f"Artifact hash not found in the unified log")

    proof = compute_inclusion_proof(all_hashes_hex, target_hex)
    if proof is None:
        raise HTTPException(404, "Could not compute inclusion proof")

    # Find the entry metadata
    idx = all_hashes_hex.index(target_hex)
    entry = entries[idx]

    return {
        **proof,
        "artifact_type": entry.artifact_type,
        "artifact_id": entry.artifact_id,
        "agent_kid": entry.agent_kid,
        "log_seq": entry.seq,
    }


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


