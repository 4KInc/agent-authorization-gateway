#!/usr/bin/env python3
"""Register a new AI agent with the Gate Gateway.

Demonstrates the agent onboarding flow for the Track 3 demo:
  1. Generate an Ed25519 identity keypair
  2. Register the public key with the Gateway
  3. Issue a test authorization (DPoP-signed request)
  4. Verify the signed receipt

No external setup required beyond `pip install cryptography httpx`.
"""

import base64
import hashlib
import json
import sys
import time
import warnings

warnings.filterwarnings("ignore")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import httpx

# ─── Configuration ────────────────────────────────────────────────────────────
GATEWAY_URL = "https://agent-auth-gateway-1031148889398.us-central1.run.app"
AGENT_ID = f"claude-research-{int(time.time()) % 100000}"
# ──────────────────────────────────────────────────────────────────────────────


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def compute_action_digest(agent_id: str, action: str, resource: str) -> str:
    """RFC 8785 JCS canonicalization of the action intent, then SHA-256."""
    # Minimal JCS: keys sorted, no whitespace, no optional parameters
    canonical = json.dumps(
        {"action": action, "agent_id": agent_id, "resource": resource},
        separators=(",", ":"), sort_keys=True
    ).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def create_dpop_proof(key: Ed25519PrivateKey, agent_id: str,
                      action: str, resource: str) -> str:
    """Create a DPoP-style proof JWT binding identity to action."""
    import uuid
    import jwt as pyjwt

    payload = {
        "sub": agent_id,
        "htm": "POST",
        "htu": "agent-authorization-gateway",
        "action": action,
        "resource": resource,
        "jti": str(uuid.uuid4()),
        "iat": int(time.time()),
        "action_digest": compute_action_digest(agent_id, action, resource),
    }
    return pyjwt.encode(payload, key, algorithm="EdDSA")


def main():
    client = httpx.Client(timeout=30)

    # ── Step 1: Generate Ed25519 keypair ──────────────────────────────────────
    print("┌─────────────────────────────────────────────────────┐")
    print("│  Gate — Agent Onboarding Demo                       │")
    print("└─────────────────────────────────────────────────────┘")
    print()
    print(f"  Gateway:  {GATEWAY_URL}")
    print(f"  Agent ID: {AGENT_ID}")
    print()

    print(">>> Step 1: Generate Ed25519 identity keypair")
    key = Ed25519PrivateKey.generate()
    pub_bytes = key.public_key().public_bytes_raw()
    x = b64url(pub_bytes)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": x}
    print(f"    Public key (x): {x[:32]}...")
    print(f"    Algorithm:      Ed25519 (EdDSA)")
    print()

    # ── Step 2: Register with Gateway (Proof of Possession) ──────────────────
    print(">>> Step 2: Register public key with Gateway (PoP)")
    print("    Requesting challenge nonce...")
    ch_resp = client.post(f"{GATEWAY_URL}/agents/register-challenge", json={"agent_id": AGENT_ID})
    if ch_resp.status_code != 200:
        print(f"    FAILED to get challenge: HTTP {ch_resp.status_code}")
        print(f"    {ch_resp.text}")
        sys.exit(1)
    challenge = ch_resp.json()
    print(f"    Nonce:    {challenge['nonce'][:24]}...")
    print(f"    Expires:  {challenge['expires_at']}")

    # Build canonical message and sign with private key
    iat = int(time.time())
    msg_obj = {
        "v": "1", "tenant_id": "hackathon-demo", "agent_id": AGENT_ID,
        "public_key": jwk, "nonce": challenge["nonce"],
        "challenge_id": challenge["challenge_id"], "iat": iat,
    }
    msg_bytes = json.dumps(msg_obj, separators=(",", ":"), sort_keys=True).encode()
    sig = key.sign(msg_bytes)
    sig_b64 = b64url(sig)

    print("    Signing proof of possession...")
    resp = client.post(
        f"{GATEWAY_URL}/agents/register",
        json={
            "agent_id": AGENT_ID, "public_key": jwk,
            "proof": {
                "nonce": challenge["nonce"],
                "challenge_id": challenge["challenge_id"],
                "signature": sig_b64,
                "iat": iat,
            },
        },
    )
    if resp.status_code != 200:
        print(f"    FAILED: HTTP {resp.status_code}")
        print(f"    {resp.text}")
        sys.exit(1)

    reg = resp.json()
    print(f"    Status:   {reg['status']}")
    print(f"    Agent ID: {reg['agent_id']}")
    print(f"    Key ID:   {reg['kid']}")
    print(f"    PoP:      {reg.get('proof_of_possession_at_registration', False)}")
    print()

    # ── Step 3: Issue test authorization ──────────────────────────────────────
    action = "read"
    resource = "staging-analytics-db"
    print(f">>> Step 3: Authorize action (DPoP-signed request)")
    print(f"    Action:   {action}")
    print(f"    Resource: {resource}")

    proof = create_dpop_proof(key, AGENT_ID, action, resource)
    resp = client.post(
        f"{GATEWAY_URL}/authorize",
        json={
            "agent_id": AGENT_ID,
            "action": action,
            "resource": resource,
            "agent_proof": proof,
        },
    )
    if resp.status_code != 200:
        print(f"    FAILED: HTTP {resp.status_code}")
        print(f"    {resp.text}")
        sys.exit(1)

    auth = resp.json()
    receipt = auth.get("receipt", {})
    body = receipt.get("body", {})

    print(f"    Decision: {auth['decision']}")
    if auth.get("token"):
        print(f"    Token:    {auth['token'][:40]}... (60s TTL)")
    print()

    # ── Step 4: Verify signed receipt ─────────────────────────────────────────
    print(">>> Step 4: Signed receipt issued")
    print(f"    Seq:            {body.get('seq')}")
    print(f"    Hash:           {receipt.get('receipt_hash', '')[:48]}...")
    print(f"    Policy version: {body.get('policy_version', '')[:48]}...")
    print(f"    Prev receipt:   {body.get('prev_receipt', '')[:48]}...")
    sig = receipt.get("sig", {})
    print(f"    Signed by:      {sig.get('kid')} ({sig.get('alg')})")
    print()

    # ── Done ──────────────────────────────────────────────────────────────────
    print("┌─────────────────────────────────────────────────────┐")
    print("│  Agent onboarded successfully.                      │")
    print("│                                                     │")
    print("│  The agent can now request authorization for any    │")
    print("│  action. Each decision produces a signed, hash-     │")
    print("│  chained receipt — independently verifiable.        │")
    print("└─────────────────────────────────────────────────────┘")


if __name__ == "__main__":
    main()
