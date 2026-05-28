#!/usr/bin/env python3
"""Demo: Rogue Worker — attempts to bypass the Gateway.

This worker demonstrates 4 attack variants, all of which must fail
at the Protected Resource with specific 401 error codes:

(a) No token — direct request without authorization
(b) Self-forged token — signed with the rogue's own key
(c) Expired token — replay of a previously-valid token after expiry
(d) Wrong-action token — valid token for action A used on action B
"""

import base64
import json
import os
import sys
import time

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8080")
RESOURCE_URL = os.environ.get("RESOURCE_URL", "http://localhost:8081")

# For cross-action test, we need a real token from the gateway
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from gateway.identity import create_agent_proof


def run():
    print("=" * 60)
    print("  ROGUE WORKER DEMO — 4 ATTACK VARIANTS")
    print("=" * 60)

    results = []

    with httpx.Client(timeout=15) as client:
        # Attack (a): No token
        print(f"\n[a] Attack: No token (direct request without authorization)")
        resp = client.get(f"{RESOURCE_URL}/customers/c1")
        error = resp.json().get("detail", {})
        code = error.get("error", "?") if isinstance(error, dict) else "?"
        status = resp.status_code
        results.append(("No token", "401 NO_TOKEN", f"{status} {code}", status == 401 and code == "NO_TOKEN"))
        print(f"    Expected: 401 NO_TOKEN")
        print(f"    Actual:   {status} {code}")
        print(f"    Result:   {'BLOCKED' if status == 401 else 'FAILED TO BLOCK!'}")

        # Attack (b): Self-forged token
        print(f"\n[b] Attack: Self-forged token (signed with rogue's own key)")
        rogue_key = Ed25519PrivateKey.generate()
        forged = pyjwt.encode({
            "iss": "agent-authorization-gateway",
            "aud": "protected-resource",
            "sub": "rogue-agent",
            "action": "read_customer",
            "resource": "customers",
            "action_digest": "sha256:fake",
            "decision": "approve",
            "receipt_hash": "sha256:fake",
            "jti": "forged-jti",
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
        }, rogue_key, algorithm="EdDSA")
        resp = client.get(f"{RESOURCE_URL}/customers/c1", headers={
            "Authorization": f"Bearer {forged}",
        })
        error = resp.json().get("detail", {})
        code = error.get("error", "?") if isinstance(error, dict) else "?"
        status = resp.status_code
        results.append(("Self-forged token", "401 INVALID_SIGNATURE", f"{status} {code}", status == 401))
        print(f"    Expected: 401 INVALID_SIGNATURE")
        print(f"    Actual:   {status} {code}")
        print(f"    Result:   {'BLOCKED' if status == 401 else 'FAILED TO BLOCK!'}")

        # Attack (c): Expired token
        print(f"\n[c] Attack: Expired token (previously-valid, now expired)")
        expired = pyjwt.encode({
            "iss": "agent-authorization-gateway",
            "aud": "protected-resource",
            "sub": "agent-1",
            "action": "read_customer",
            "resource": "customers",
            "action_digest": "sha256:old",
            "jti": "expired-jti",
            "iat": int(time.time()) - 120,
            "exp": int(time.time()) - 60,  # expired 60 seconds ago
        }, rogue_key, algorithm="EdDSA")
        resp = client.get(f"{RESOURCE_URL}/customers/c1", headers={
            "Authorization": f"Bearer {expired}",
        })
        error = resp.json().get("detail", {})
        code = error.get("error", "?") if isinstance(error, dict) else "?"
        status = resp.status_code
        results.append(("Expired token", "401 EXPIRED", f"{status} {code}", status == 401))
        print(f"    Expected: 401 EXPIRED")
        print(f"    Actual:   {status} {code}")
        print(f"    Result:   {'BLOCKED' if status == 401 else 'FAILED TO BLOCK!'}")

        # Attack (d): Wrong-action token
        print(f"\n[d] Attack: Wrong-action token (read token used on delete endpoint)")
        # First, get a REAL token for read_customer from the Gateway
        agent_key = Ed25519PrivateKey.generate()
        pub_bytes = agent_key.public_key().public_bytes_raw()
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()}

        # Register and authorize
        client.post(f"{GATEWAY_URL}/agents/register", json={
            "agent_id": "rogue-crossaction",
            "public_key": jwk,
        })
        proof = create_agent_proof(agent_key, "rogue-crossaction", "read_customer", "customers")
        auth_resp = client.post(f"{GATEWAY_URL}/authorize", json={
            "agent_id": "rogue-crossaction",
            "action": "read_customer",
            "resource": "customers",
            "agent_proof": proof,
        })
        real_token = auth_resp.json().get("token", "")
        if real_token:
            # Use this read_customer token on the delete endpoint
            resp = client.delete(f"{RESOURCE_URL}/customers/c1", headers={
                "Authorization": f"Bearer {real_token}",
            })
            error = resp.json().get("detail", {})
            code = error.get("error", "?") if isinstance(error, dict) else "?"
            status = resp.status_code
            results.append(("Wrong-action token", "401 WRONG_ACTION", f"{status} {code}", status == 401))
            print(f"    Expected: 401 WRONG_ACTION")
            print(f"    Actual:   {status} {code}")
            print(f"    Result:   {'BLOCKED' if status == 401 else 'FAILED TO BLOCK!'}")
        else:
            results.append(("Wrong-action token", "401 WRONG_ACTION", "NO TOKEN", False))
            print(f"    Could not get a real token from Gateway")

    # Summary table
    print(f"\n{'=' * 60}")
    print(f"  RESULTS SUMMARY")
    print(f"{'=' * 60}")
    print(f"  {'Attack':<25} {'Expected':<22} {'Actual':<22} {'Status'}")
    print(f"  {'-'*25} {'-'*22} {'-'*22} {'-'*8}")
    all_blocked = True
    for attack, expected, actual, blocked in results:
        status = "BLOCKED" if blocked else "FAIL"
        if not blocked:
            all_blocked = False
        print(f"  {attack:<25} {expected:<22} {actual:<22} {status}")
    print(f"\n  Overall: {'ALL ATTACKS BLOCKED' if all_blocked else 'SOME ATTACKS SUCCEEDED — ENFORCEMENT FAILED'}")
    print(f"{'=' * 60}")

    return 0 if all_blocked else 1


if __name__ == "__main__":
    sys.exit(run())
