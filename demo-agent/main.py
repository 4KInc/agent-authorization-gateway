"""Demo agent service for Gate Track 3 submission.

Self-contained Cloud Run service that:
1. Generates an Ed25519 keypair at startup
2. Serves /.well-known/agent-card.json with the declared public key
3. Has /attack-resource endpoint that submits authorize requests to Gate
4. Has /resource-reachability/{id} endpoint for resource verification shim
"""

import base64
import hashlib
import json
import os
import time
import uuid

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

PRIVATE_KEY = Ed25519PrivateKey.generate()
PUB_BYTES = PRIVATE_KEY.public_key().public_bytes_raw()
PUB_JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": base64.urlsafe_b64encode(PUB_BYTES).rstrip(b"=").decode(),
}

GATEWAY_URL = os.environ.get("GATEWAY_URL", "https://agent-auth-gateway-1031148889398.us-central1.run.app")
SERVICE_URL = os.environ.get("SERVICE_URL", "")
AGENT_NAME = os.environ.get("AGENT_NAME", "demo-acme-analytics-agent")


@app.get("/.well-known/agent-card.json")
def agent_card():
    return {
        "version": "0.4.0",
        "name": AGENT_NAME,
        "description": "Demo AI agent for Gate Track 3 - financial analytics worker",
        "url": SERVICE_URL,
        "signing_key": PUB_JWK,
        "skills": [
            {"id": "read_analytics", "description": "Read analytics data from staging databases"},
            {"id": "summarize_report", "description": "Generate summary reports from analytics"},
        ],
        "input_modes": ["text"],
        "output_modes": ["text"],
    }


@app.get("/health")
def health():
    return {"ok": True, "agent": AGENT_NAME, "public_key": PUB_JWK}


@app.get("/public-key")
def public_key():
    return PUB_JWK


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


def _jcs(obj):
    if obj is None: return "null"
    if isinstance(obj, bool): return "true" if obj else "false"
    if isinstance(obj, int): return str(obj)
    if isinstance(obj, str): return json.dumps(obj)
    if isinstance(obj, list): return "[" + ",".join(_jcs(i) for i in obj) + "]"
    if isinstance(obj, dict): return "{" + ",".join(json.dumps(k)+":"+_jcs(obj[k]) for k in sorted(obj.keys())) + "}"


class AttackRequest(BaseModel):
    action: str = "delete"
    resource: str = "gcp-cloudsql-demo-customers"


@app.post("/attack-resource")
async def attack_resource(req: AttackRequest):
    """The agent attempts to authorize an action. Uses PyJWT for proper DPoP."""
    import jwt as pyjwt

    # Compute action digest
    intent_canonical = _jcs({"action": req.action, "agent_id": AGENT_NAME, "resource": req.resource})
    action_digest = "sha256:" + hashlib.sha256(intent_canonical.encode()).hexdigest()

    # Build DPoP proof JWT using PyJWT
    proof = pyjwt.encode(
        {
            "sub": AGENT_NAME,
            "htm": "POST",
            "htu": "agent-authorization-gateway",
            "action": req.action,
            "resource": req.resource,
            "jti": str(uuid.uuid4()),
            "iat": int(time.time()),
            "action_digest": action_digest,
        },
        PRIVATE_KEY,
        algorithm="EdDSA",
    )

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(f"{GATEWAY_URL}/authorize", json={
            "agent_id": AGENT_NAME,
            "action": req.action,
            "resource": req.resource,
            "agent_proof": proof,
        })
        result = resp.json()

    return {
        "agent": AGENT_NAME,
        "attempted_action": req.action,
        "attempted_resource": req.resource,
        "gateway_status": resp.status_code,
        "gateway_response": result,
        "decision": result.get("decision"),
        "reason_codes": result.get("reason_codes", []),
    }


class RegisterSelfRequest(BaseModel):
    tenant: str = "hackathon-demo"


@app.post("/register-self")
@app.post("/self-register")
async def register_self(req: RegisterSelfRequest):
    """Register this agent with the Gateway via the PoP flow.

    Performs two-step challenge-response with the agent's own keypair,
    including agent_card_url for existence verification.
    """
    async with httpx.AsyncClient(timeout=15.0) as client:
        ch_resp = await client.post(f"{GATEWAY_URL}/agents/register-challenge", json={"agent_id": AGENT_NAME})
        if ch_resp.status_code != 200:
            raise HTTPException(502, f"challenge failed: {ch_resp.status_code} {ch_resp.text}")
        ch = ch_resp.json()

        iat = int(time.time())
        card_url = f"{SERVICE_URL}/.well-known/agent-card.json" if SERVICE_URL else None
        msg = _jcs({
            "v": "1", "tenant_id": req.tenant, "agent_id": AGENT_NAME,
            "public_key": PUB_JWK, "nonce": ch["nonce"],
            "challenge_id": ch["challenge_id"], "iat": iat,
        }).encode()
        sig = base64.urlsafe_b64encode(PRIVATE_KEY.sign(msg)).rstrip(b"=").decode()

        reg_resp = await client.post(f"{GATEWAY_URL}/agents/register", json={
            "agent_id": AGENT_NAME, "public_key": PUB_JWK,
            "agent_card_url": card_url,
            "proof": {"nonce": ch["nonce"], "challenge_id": ch["challenge_id"], "signature": sig, "iat": iat},
        })
        if reg_resp.status_code != 200:
            raise HTTPException(502, f"registration failed: {reg_resp.status_code} {reg_resp.text}")

        result = reg_resp.json()
        return {
            "agent_id": AGENT_NAME,
            "kid": result.get("kid"),
            "proof_of_possession_at_registration": result.get("proof_of_possession_at_registration"),
            "agent_card_verification": result.get("agent_card_verification"),
            "agent_card_verification_reason": result.get("agent_card_verification_reason"),
            "agent_card_url": card_url,
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
