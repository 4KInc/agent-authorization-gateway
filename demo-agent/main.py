"""Demo agent service for Gate Track 3 submission.

Self-contained Cloud Run service that:
1. Spawns fresh Ed25519 agents on demand via POST /spawn
2. Each agent gets a unique identity, A2A card, and live-challenge endpoint
3. Agents self-register with the Gateway via the PoP flow
4. Has /attack-resource endpoint that submits authorize requests using the agent's own key
"""

import base64
import hashlib
import json
import os
import random
import time
import uuid

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

GATEWAY_URL = os.environ.get("GATEWAY_URL", "https://agent-auth-gateway-1031148889398.us-central1.run.app")
SERVICE_URL = os.environ.get("SERVICE_URL", "")
LEGACY_NAME = "demo-acme-analytics-agent"

# --- Agent Registry (in-memory) ---

_ADJECTIVES = [
    "alpha", "beta", "gamma", "delta", "swift", "prime", "nova", "apex",
    "core", "pulse", "flux", "spark", "nexus", "arc", "zen", "vibe",
]
_ROLES = [
    "analyst", "auditor", "planner", "scanner", "watcher", "builder",
    "reader", "indexer", "monitor", "mapper", "ranger", "scout",
]

_agents: dict[str, dict] = {}  # agent_id -> {private_key, pub_jwk, name, created_at}


def _make_pub_jwk(private_key: Ed25519PrivateKey) -> dict:
    pub_bytes = private_key.public_key().public_bytes_raw()
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode(),
    }


def _generate_agent_name() -> str:
    adj = random.choice(_ADJECTIVES)
    role = random.choice(_ROLES)
    suffix = uuid.uuid4().hex[:4]
    return f"agent-{adj}-{role}-{suffix}"


def _jcs(obj):
    if obj is None: return "null"
    if isinstance(obj, bool): return "true" if obj else "false"
    if isinstance(obj, int): return str(obj)
    if isinstance(obj, str): return json.dumps(obj)
    if isinstance(obj, list): return "[" + ",".join(_jcs(i) for i in obj) + "]"
    if isinstance(obj, dict): return "{" + ",".join(json.dumps(k)+":"+_jcs(obj[k]) for k in sorted(obj.keys())) + "}"


# --- Endpoints ---

@app.get("/health")
def health():
    return {"ok": True, "agents_spawned": len(_agents)}


@app.post("/spawn")
async def spawn():
    """Spawn a fresh AI agent with a unique Ed25519 identity and self-register with the Gateway."""
    private_key = Ed25519PrivateKey.generate()
    pub_jwk = _make_pub_jwk(private_key)
    agent_name = _generate_agent_name()

    _agents[agent_name] = {
        "private_key": private_key,
        "pub_jwk": pub_jwk,
        "name": agent_name,
        "created_at": time.time(),
    }

    card_url = f"{SERVICE_URL}/a/{agent_name}/.well-known/agent-card.json" if SERVICE_URL else None
    challenge_url = f"{SERVICE_URL}/a/{agent_name}/live-challenge" if SERVICE_URL else None

    # Self-register with Gateway via PoP challenge-response
    reg_result = {}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            ch_resp = await client.post(f"{GATEWAY_URL}/agents/register-challenge", json={"agent_id": agent_name})
            if ch_resp.status_code != 200:
                raise Exception(f"challenge failed: {ch_resp.status_code} {ch_resp.text}")
            ch = ch_resp.json()

            iat = int(time.time())
            msg = _jcs({
                "v": "1", "tenant_id": "hackathon-demo", "agent_id": agent_name,
                "public_key": pub_jwk, "nonce": ch["nonce"],
                "challenge_id": ch["challenge_id"], "iat": iat,
            }).encode()
            sig = base64.urlsafe_b64encode(private_key.sign(msg)).rstrip(b"=").decode()

            reg_resp = await client.post(f"{GATEWAY_URL}/agents/register", json={
                "agent_id": agent_name, "public_key": pub_jwk,
                "agent_card_url": card_url,
                "live_challenge_url": challenge_url,
                "proof": {"nonce": ch["nonce"], "challenge_id": ch["challenge_id"], "signature": sig, "iat": iat},
            })
            if reg_resp.status_code != 200:
                raise Exception(f"registration failed: {reg_resp.status_code} {reg_resp.text}")
            reg_result = reg_resp.json()
    except Exception as e:
        # Clean up on failure
        _agents.pop(agent_name, None)
        raise HTTPException(502, f"Gateway registration failed: {e}")

    return {
        "agent_id": agent_name,
        "kid": reg_result.get("kid"),
        "public_key": pub_jwk,
        "card_url": card_url,
        "live_challenge_url": challenge_url,
        "card_verification": reg_result.get("agent_card_verification"),
        "live_verification": reg_result.get("live_challenge_verification"),
        "pop": reg_result.get("proof_of_possession_at_registration"),
    }


# --- Per-agent A2A card ---

@app.get("/a/{agent_id}/.well-known/agent-card.json")
def agent_card(agent_id: str):
    agent = _agents.get(agent_id)
    if not agent:
        raise HTTPException(404, f"Agent {agent_id} not found")
    return {
        "version": "0.4.0",
        "name": agent_id,
        "description": f"Dynamically spawned AI agent — {agent_id}",
        "url": f"{SERVICE_URL}/a/{agent_id}" if SERVICE_URL else "",
        "signing_key": agent["pub_jwk"],
        "skills": [
            {"id": "read_analytics", "description": "Read analytics data from staging databases"},
            {"id": "summarize_report", "description": "Generate summary reports from analytics"},
        ],
        "input_modes": ["text"],
        "output_modes": ["text"],
    }


# --- Per-agent live challenge ---

class LiveChallengeRequest(BaseModel):
    v: str
    type: str
    tenant_id: str
    agent_id: str
    nonce: str
    challenge_id: str
    iat: int


@app.post("/a/{agent_id}/live-challenge")
async def agent_live_challenge(agent_id: str, challenge: LiveChallengeRequest):
    agent = _agents.get(agent_id)
    if not agent:
        raise HTTPException(404, f"Agent {agent_id} not found")
    if abs(int(time.time()) - challenge.iat) > 60:
        raise HTTPException(400, "challenge timestamp out of window")
    if challenge.agent_id != agent_id:
        raise HTTPException(400, f"challenge for {challenge.agent_id}, not {agent_id}")

    canonical = json.dumps(
        challenge.model_dump(), separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")
    signature = agent["private_key"].sign(canonical)
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return {"signature": sig_b64, "agent_id": agent_id, "challenge_id": challenge.challenge_id}


# --- Per-agent attack-resource ---

class AttackRequest(BaseModel):
    agent_id: str = LEGACY_NAME
    action: str = "read"
    resource: str = "staging-database"


@app.post("/attack-resource")
async def attack_resource(req: AttackRequest):
    """An agent attempts to authorize an action via the Gateway."""
    import jwt as pyjwt

    agent = _agents.get(req.agent_id)
    if not agent:
        raise HTTPException(404, f"Agent {req.agent_id} not found. Spawn it first via POST /spawn.")

    private_key = agent["private_key"]

    intent_canonical = _jcs({"action": req.action, "agent_id": req.agent_id, "resource": req.resource})
    action_digest = "sha256:" + hashlib.sha256(intent_canonical.encode()).hexdigest()

    proof = pyjwt.encode(
        {
            "sub": req.agent_id,
            "htm": "POST",
            "htu": "agent-authorization-gateway",
            "action": req.action,
            "resource": req.resource,
            "jti": str(uuid.uuid4()),
            "iat": int(time.time()),
            "action_digest": action_digest,
        },
        private_key,
        algorithm="EdDSA",
    )

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(f"{GATEWAY_URL}/authorize", json={
            "agent_id": req.agent_id,
            "action": req.action,
            "resource": req.resource,
            "agent_proof": proof,
        })
        result = resp.json()

    return {
        "agent": req.agent_id,
        "attempted_action": req.action,
        "attempted_resource": req.resource,
        "gateway_status": resp.status_code,
        "gateway_response": result,
        "decision": result.get("decision"),
        "reason_codes": result.get("reason_codes", []),
    }


# --- Legacy endpoints for backward compatibility ---

LEGACY_KEY = Ed25519PrivateKey.generate()
LEGACY_PUB = _make_pub_jwk(LEGACY_KEY)

# Pre-register legacy agent in _agents so card/challenge work
_agents[LEGACY_NAME] = {
    "private_key": LEGACY_KEY,
    "pub_jwk": LEGACY_PUB,
    "name": LEGACY_NAME,
    "created_at": time.time(),
}


@app.get("/.well-known/agent-card.json")
def legacy_agent_card():
    return agent_card(LEGACY_NAME)


@app.post("/live-challenge")
async def legacy_live_challenge(challenge: LiveChallengeRequest):
    return await agent_live_challenge(LEGACY_NAME, challenge)


@app.get("/public-key")
def public_key():
    return LEGACY_PUB


KNOWN_RESOURCES = {
    "gcp-cloudsql-demo-customers": {
        "type": "cloudsql",
        "connection_name": "quick-catcher-470218-b0:us-central1:demo-customers-db",
        "database": "demo",
    },
}


@app.get("/resource-reachability/{resource_id}")
def resource_reachability(resource_id: str):
    if resource_id not in KNOWN_RESOURCES:
        raise HTTPException(404, "resource not known")
    from datetime import datetime, timezone
    return {
        "resource_id": resource_id,
        "reachable": True,
        "metadata": KNOWN_RESOURCES[resource_id],
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


class RegisterSelfRequest(BaseModel):
    tenant: str = "hackathon-demo"


@app.post("/register-self")
@app.post("/self-register")
async def register_self(req: RegisterSelfRequest):
    """Legacy: register the default demo agent."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        ch_resp = await client.post(f"{GATEWAY_URL}/agents/register-challenge", json={"agent_id": LEGACY_NAME})
        if ch_resp.status_code != 200:
            raise HTTPException(502, f"challenge failed: {ch_resp.status_code} {ch_resp.text}")
        ch = ch_resp.json()

        iat = int(time.time())
        card_url = f"{SERVICE_URL}/.well-known/agent-card.json" if SERVICE_URL else None
        msg = _jcs({
            "v": "1", "tenant_id": req.tenant, "agent_id": LEGACY_NAME,
            "public_key": LEGACY_PUB, "nonce": ch["nonce"],
            "challenge_id": ch["challenge_id"], "iat": iat,
        }).encode()
        sig = base64.urlsafe_b64encode(LEGACY_KEY.sign(msg)).rstrip(b"=").decode()

        challenge_url = f"{SERVICE_URL}/live-challenge" if SERVICE_URL else None
        reg_resp = await client.post(f"{GATEWAY_URL}/agents/register", json={
            "agent_id": LEGACY_NAME, "public_key": LEGACY_PUB,
            "agent_card_url": card_url,
            "live_challenge_url": challenge_url,
            "proof": {"nonce": ch["nonce"], "challenge_id": ch["challenge_id"], "signature": sig, "iat": iat},
        })
        if reg_resp.status_code != 200:
            raise HTTPException(502, f"registration failed: {reg_resp.status_code} {reg_resp.text}")

        result = reg_resp.json()
        return {
            "agent_id": LEGACY_NAME,
            "kid": result.get("kid"),
            "proof_of_possession_at_registration": result.get("proof_of_possession_at_registration"),
            "agent_card_verification": result.get("agent_card_verification"),
            "agent_card_verification_reason": result.get("agent_card_verification_reason"),
            "agent_card_url": card_url,
            "live_challenge_verification": result.get("live_challenge_verification"),
            "live_challenge_verification_reason": result.get("live_challenge_verification_reason"),
            "live_challenge_url": challenge_url,
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
