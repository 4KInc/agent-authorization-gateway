#!/usr/bin/env python3
"""Demo: Compliant Worker — follows the authorize-then-execute flow.

This worker:
1. Registers its identity with the Gateway
2. Creates a DPoP proof for each action
3. Gets authorization (token + receipt) from the Gateway
4. Uses the token against the Protected Resource
5. Demonstrates: approve (read), approve (list), deny (delete-all)
"""

import base64
import json
import os
import sys

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from gateway.identity import create_agent_proof, build_registration_message

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8080")
RESOURCE_URL = os.environ.get("RESOURCE_URL", "http://localhost:8081")
AGENT_ID = "compliant-worker-01"


def make_jwk(private_key: Ed25519PrivateKey) -> dict:
    pub_bytes = private_key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


def register_with_pop(client, gateway_url, agent_id, private_key, jwk, tenant="hackathon-demo"):
    """Two-step challenge-response registration with proof of possession."""
    import time as _t
    ch = client.post(f"{gateway_url}/agents/register-challenge", json={"agent_id": agent_id}).json()
    iat = int(_t.time())
    msg = build_registration_message(tenant, agent_id, jwk, ch["nonce"], ch["challenge_id"], iat)
    sig = private_key.sign(msg)
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    resp = client.post(f"{gateway_url}/agents/register", json={
        "agent_id": agent_id, "public_key": jwk,
        "proof": {"nonce": ch["nonce"], "challenge_id": ch["challenge_id"], "signature": sig_b64, "iat": iat},
    })
    return resp.json()


def run():
    print("=" * 60)
    print("  COMPLIANT WORKER DEMO")
    print("=" * 60)

    # Generate identity
    agent_key = Ed25519PrivateKey.generate()
    jwk = make_jwk(agent_key)

    with httpx.Client(timeout=15) as client:
        # Step 1: Register with Gateway (proof of possession)
        print(f"\n[1] Registering {AGENT_ID} with Gateway (PoP)...")
        reg = register_with_pop(client, GATEWAY_URL, AGENT_ID, agent_key, jwk)
        print(f"    Registered: kid={reg.get('kid', '?')} pop={reg.get('proof_of_possession_at_registration', False)}")

        # Step 2: Authorize read_customer (should APPROVE)
        print(f"\n[2] Authorizing: read on staging-database...")
        proof = create_agent_proof(agent_key, AGENT_ID, "read", "staging-database")
        resp = client.post(f"{GATEWAY_URL}/authorize", json={
            "agent_id": AGENT_ID,
            "action": "read",
            "resource": "staging-database",
            "agent_proof": proof,
        })
        auth = resp.json()
        print(f"    Decision: {auth['decision']}")
        print(f"    Receipt:  {auth['receipt_hash'][:40]}...")
        token = auth.get("token")

        if token:
            # Step 3: Use token against Protected Resource
            print(f"\n[3] Using token to read customer c1...")
            resp = client.get(f"{RESOURCE_URL}/customers/c1", headers={
                "Authorization": f"Bearer {token}",
            })
            if resp.status_code == 200:
                cust = resp.json()
                print(f"    Got customer: {cust.get('customer', {}).get('name', '?')}")
                print(f"    Authorized by: {cust.get('authorized_by', '?')}")
            else:
                print(f"    Resource returned: {resp.status_code} {resp.text[:100]}")

        # Step 4: Authorize delete (should DENY)
        print(f"\n[4] Authorizing: delete_all on customers (should be DENIED)...")
        proof = create_agent_proof(agent_key, AGENT_ID, "delete_all", "customers")
        resp = client.post(f"{GATEWAY_URL}/authorize", json={
            "agent_id": AGENT_ID,
            "action": "delete_all",
            "resource": "customers",
            "agent_proof": proof,
        })
        auth = resp.json()
        print(f"    Decision: {auth['decision']}")
        print(f"    Reasons:  {auth.get('reason_codes', [])}")
        print(f"    Token:    {'NONE (correctly withheld)' if not auth.get('token') else 'ERROR: token issued!'}")

        # Step 5: Show chain stats
        print(f"\n[5] Chain stats:")
        resp = client.get(f"{GATEWAY_URL}/stats")
        stats = resp.json()
        for k, v in stats.items():
            print(f"    {k}: {v}")

    print(f"\n{'=' * 60}")
    print("  COMPLIANT WORKER: ALL STEPS COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    run()
