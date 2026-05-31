#!/usr/bin/env python3
"""Demo: Resource Registry Lifecycle.

Demonstrates:
1. Register an agent
2. Switch policy to require_resource_registration: true
3. Attempt authorization for unregistered resource -> DENY with RESOURCE_NOT_REGISTERED
4. Register the resource
5. Attempt authorization for the now-registered resource -> APPROVE
6. Revoke the resource
7. Attempt authorization again -> DENY with RESOURCE_NOT_REGISTERED
8. Switch policy back to require_resource_registration: false
9. Attempt authorization again -> APPROVE (permissive mode accepts unregistered)
"""

import base64
import json
import os
import sys

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from gateway.identity import create_agent_proof

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8080")
AGENT_ID = "resource-demo-agent"
RESOURCE_ID = "staging-demo-resource"


def make_jwk(private_key: Ed25519PrivateKey) -> dict:
    pub_bytes = private_key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


def step(num, desc):
    print(f"\n{'='*60}")
    print(f"  STEP {num}: {desc}")
    print(f"{'='*60}")


def run():
    print("=" * 60)
    print("  RESOURCE REGISTRY LIFECYCLE DEMO")
    print("=" * 60)

    agent_key = Ed25519PrivateKey.generate()
    jwk = make_jwk(agent_key)

    with httpx.Client(timeout=30) as client:
        # Save original policy to restore later
        original_policy = client.get(f"{GATEWAY_URL}/policy").json()

        # Step 1: Register agent
        step(1, "Register agent identity")
        resp = client.post(f"{GATEWAY_URL}/agents/register", json={
            "agent_id": AGENT_ID,
            "public_key": jwk,
        })
        reg = resp.json()
        if resp.status_code == 409:
            print(f"    Agent already registered (reusing)")
        else:
            print(f"    Registered: kid={reg.get('kid', '?')}")

        # Step 2: Enable strict resource registration
        step(2, "Enable require_resource_registration: true")
        policy_rules = original_policy.get("rules", [])
        resp = client.put(f"{GATEWAY_URL}/policy", json={
            "version": original_policy.get("version", "1"),
            "rules": policy_rules,
            "require_resource_registration": True,
        })
        print(f"    Policy updated: {resp.json()}")

        # Step 3: Try to authorize an unregistered resource -> DENIED
        step(3, "Authorize UNREGISTERED resource -> expect DENY")
        proof = create_agent_proof(agent_key, AGENT_ID, "read", RESOURCE_ID)
        resp = client.post(f"{GATEWAY_URL}/authorize", json={
            "agent_id": AGENT_ID,
            "action": "read",
            "resource": RESOURCE_ID,
            "agent_proof": proof,
        })
        auth = resp.json()
        decision = auth.get("decision", auth.get("detail", "error"))
        reasons = auth.get("reason_codes", [])
        print(f"    Decision: {decision}")
        print(f"    Reasons:  {reasons}")
        assert "RESOURCE_NOT_REGISTERED" in str(reasons) or "RESOURCE_NOT_REGISTERED" in str(decision), \
            f"Expected RESOURCE_NOT_REGISTERED, got {decision} {reasons}"
        print(f"    CORRECT: Unregistered resource blocked")

        # Step 4: Register the resource
        step(4, "Register the resource")
        resp = client.post(f"{GATEWAY_URL}/resources/register", json={
            "resource_id": RESOURCE_ID,
            "display_name": "Staging Demo Resource",
            "description": "Created by resource lifecycle demo",
            "resource_type": "database",
            "owner": "demo-team",
        })
        reg_result = resp.json()
        print(f"    Registered: {json.dumps(reg_result, indent=6)}")

        # Step 5: Authorize the now-registered resource -> APPROVED
        step(5, "Authorize REGISTERED resource -> expect APPROVE")
        proof = create_agent_proof(agent_key, AGENT_ID, "read", RESOURCE_ID)
        resp = client.post(f"{GATEWAY_URL}/authorize", json={
            "agent_id": AGENT_ID,
            "action": "read",
            "resource": RESOURCE_ID,
            "agent_proof": proof,
        })
        auth = resp.json()
        print(f"    Decision: {auth['decision']}")
        assert auth["decision"] == "approve", f"Expected approve, got {auth['decision']}"
        body = auth.get("receipt", {}).get("body", {})
        print(f"    resource_registration_id: {body.get('resource_registration_id', 'N/A')}")
        print(f"    Token issued: {'yes' if auth.get('token') else 'no'}")
        print(f"    CORRECT: Registered resource approved")

        # Step 6: Revoke the resource
        step(6, "Revoke the resource")
        resp = client.delete(f"{GATEWAY_URL}/resources/{RESOURCE_ID}")
        print(f"    Revoked: {resp.json()}")

        # Step 7: Authorize revoked resource -> DENIED
        step(7, "Authorize REVOKED resource -> expect DENY")
        proof = create_agent_proof(agent_key, AGENT_ID, "read", RESOURCE_ID)
        resp = client.post(f"{GATEWAY_URL}/authorize", json={
            "agent_id": AGENT_ID,
            "action": "read",
            "resource": RESOURCE_ID,
            "agent_proof": proof,
        })
        auth = resp.json()
        decision = auth.get("decision", auth.get("detail", "error"))
        reasons = auth.get("reason_codes", [])
        print(f"    Decision: {decision}")
        print(f"    Reasons:  {reasons}")
        assert "RESOURCE_NOT_REGISTERED" in str(reasons) or "RESOURCE_NOT_REGISTERED" in str(decision), \
            f"Expected RESOURCE_NOT_REGISTERED, got {decision} {reasons}"
        print(f"    CORRECT: Revoked resource blocked")

        # Step 8: Switch back to permissive mode
        step(8, "Disable strict mode: require_resource_registration: false")
        resp = client.put(f"{GATEWAY_URL}/policy", json={
            "version": original_policy.get("version", "1"),
            "rules": policy_rules,
            "require_resource_registration": False,
        })
        print(f"    Policy updated: {resp.json()}")

        # Step 9: Authorize again in permissive mode -> APPROVED
        step(9, "Authorize in PERMISSIVE mode -> expect APPROVE")
        proof = create_agent_proof(agent_key, AGENT_ID, "read", RESOURCE_ID)
        resp = client.post(f"{GATEWAY_URL}/authorize", json={
            "agent_id": AGENT_ID,
            "action": "read",
            "resource": RESOURCE_ID,
            "agent_proof": proof,
        })
        auth = resp.json()
        print(f"    Decision: {auth['decision']}")
        assert auth["decision"] == "approve", f"Expected approve, got {auth['decision']}"
        print(f"    Token issued: {'yes' if auth.get('token') else 'no'}")
        print(f"    CORRECT: Permissive mode allows unregistered resources")

        # Restore original policy
        client.put(f"{GATEWAY_URL}/policy", json={
            "version": original_policy.get("version", "1"),
            "rules": policy_rules,
            "require_resource_registration": original_policy.get("require_resource_registration", False),
        })

    print(f"\n{'='*60}")
    print("  RESOURCE LIFECYCLE DEMO: ALL 9 STEPS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    run()
