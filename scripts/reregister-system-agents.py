#!/usr/bin/env python3
"""Bootstrap re-registration of Gate system agents with proof of possession.

KNOWN LIMITATION: This script registers system agents in the agent registry
with PoP, but the resulting kid (`agent-{hash}`) does not match the live
signing kid used to sign receipts and other artifacts (e.g.,
`gateway-hackathon-demo-{hash}`, `auditor-{hash}`). This is because the
registration endpoint applies a fixed `agent-` prefix, while live signing
keys use service-specific prefixes managed via Secret Manager.

The current architecture treats system agent identity as deployment-managed
(Secret Manager + service-specific kid prefixes) and customer agent identity
as registry-managed (PoP + `agent-` prefix). This separation is intentional.

Unifying the two would require either:
  (a) accepting an explicit kid_prefix on the registration endpoint, or
  (b) detecting that the submitted key matches a known service key.
Both are v1.0 roadmap items.

This script is retained as a reference implementation of the PoP flow
against system agent keys.

For each system agent, reads its private key from Secret Manager, derives
the public key, performs the two-step PoP exchange, and verifies the result.

The registered kid (agent-xxx) will differ from the signing kid
(gateway-hackathon-demo-xxx, auditor-xxx, etc.) because the registry uses
a different derivation scheme. This is expected — the purpose is to prove
key control, not to alias the signing kid.

Usage:
    python3 scripts/reregister-system-agents.py --tenant=hackathon-demo \\
        --gateway-url=https://agent-auth-gateway-1031148889398.us-central1.run.app \\
        --agent=gateway

    python3 scripts/reregister-system-agents.py --tenant=hackathon-demo \\
        --gateway-url=https://agent-auth-gateway-1031148889398.us-central1.run.app \\
        --all
"""

import argparse
import base64
import json
import subprocess
import sys
import time

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

SYSTEM_AGENTS = {
    "gateway": {
        "agent_id": "system-gateway",
        "secret_name": "gateway-signing-key",
        "key_format": "pem",
        "key_endpoint": "/keys",
        "service_url": "https://agent-auth-gateway-1031148889398.us-central1.run.app",
    },
    "auditor": {
        "agent_id": "system-auditor",
        "secret_name": "gateway-auditor-signing-key",
        "key_format": "base64",
        "key_endpoint": "/audit-keys",
        "service_url": "https://agent-auth-gateway-auditor-1031148889398.us-central1.run.app",
    },
    "recommender": {
        "agent_id": "system-recommender",
        "secret_name": "gateway-recommender-signing-key",
        "key_format": "base64",
        "key_endpoint": "/recommender-keys",
        "service_url": "https://agent-auth-gateway-recommender-1031148889398.us-central1.run.app",
    },
    "investigator": {
        "agent_id": "system-investigator",
        "secret_name": "gateway-investigator-signing-key",
        "key_format": "base64",
        "key_endpoint": "/investigator-keys",
        "service_url": "https://agent-auth-investigator-1031148889398.us-central1.run.app",
    },
    "coordinator": {
        "agent_id": "system-coordinator",
        "secret_name": "gateway-coordinator-signing-key",
        "key_format": "base64",
        "key_endpoint": "/coordinator-keys",
        "service_url": "https://agent-auth-gateway-coordinator-1031148889398.us-central1.run.app",
    },
}


def load_private_key(secret_name: str, key_format: str, project: str):
    """Read a private key from Secret Manager."""
    result = subprocess.run([
        "gcloud", "secrets", "versions", "access", "latest",
        f"--secret={secret_name}", f"--project={project}",
    ], capture_output=True, text=True, check=True)
    secret = json.loads(result.stdout)
    signing_kid = secret.get("kid", "unknown")

    if key_format == "pem":
        pk = load_pem_private_key(secret["private_pem"].encode(), password=None)
    else:
        priv_bytes = base64.b64decode(secret["private_key"])
        pk = Ed25519PrivateKey.from_private_bytes(priv_bytes)

    return pk, signing_kid


def make_jwk(pk: Ed25519PrivateKey) -> dict:
    pub_bytes = pk.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


def canonicalize(obj):
    """Minimal JCS canonicalization matching gateway/canonical.py."""
    if obj is None: return "null"
    if isinstance(obj, bool): return "true" if obj else "false"
    if isinstance(obj, int): return str(obj)
    if isinstance(obj, str): return json.dumps(obj)
    if isinstance(obj, list): return "[" + ",".join(canonicalize(i) for i in obj) + "]"
    if isinstance(obj, dict):
        return "{" + ",".join(json.dumps(k) + ":" + canonicalize(obj[k]) for k in sorted(obj.keys())) + "}"
    raise ValueError(f"Unsupported: {type(obj)}")


def bootstrap_agent(name: str, config: dict, project: str, tenant: str, gateway_url: str):
    print(f"\n{'='*60}")
    print(f"  Bootstrapping: {name} (agent_id={config['agent_id']})")
    print(f"{'='*60}")

    # 1. Load private key
    print(f"  [1] Loading secret {config['secret_name']}...")
    pk, signing_kid = load_private_key(config["secret_name"], config["key_format"], project)
    print(f"      Signing kid: {signing_kid}")

    # 2. Derive JWK
    jwk = make_jwk(pk)
    print(f"  [2] JWK x: {jwk['x'][:24]}...")

    # 3. Verify live kid matches secret kid
    print(f"  [3] Fetching live kid from {config['key_endpoint']}...")
    try:
        r = httpx.get(f"{config['service_url']}{config['key_endpoint']}", timeout=15)
        r.raise_for_status()
        keys_data = r.json()
        if "keys" in keys_data and keys_data["keys"]:
            live_kid = keys_data["keys"][0]["kid"]
        else:
            live_kid = keys_data.get("kid", "?")
        print(f"      Live kid: {live_kid}")
        if live_kid != signing_kid:
            print(f"  WARNING: live kid ({live_kid}) != secret kid ({signing_kid})")
            print(f"  Proceeding — signing kid from secret is authoritative.")
    except Exception as e:
        print(f"      Could not fetch live kid: {e}")
        print(f"      Using secret kid: {signing_kid}")

    # 4. Fetch challenge
    print(f"  [4] Fetching challenge...")
    ch_resp = httpx.post(f"{gateway_url}/agents/register-challenge",
                         json={"agent_id": config["agent_id"]}, timeout=15)
    if ch_resp.status_code != 200:
        print(f"  FAIL: challenge returned {ch_resp.status_code}: {ch_resp.text}")
        sys.exit(1)
    ch = ch_resp.json()
    print(f"      Nonce: {ch['nonce'][:16]}...")

    # 5. Build canonical message and sign
    iat = int(time.time())
    msg_obj = {
        "v": "1",
        "tenant_id": tenant,
        "agent_id": config["agent_id"],
        "public_key": jwk,
        "nonce": ch["nonce"],
        "challenge_id": ch["challenge_id"],
        "iat": iat,
    }
    msg_bytes = canonicalize(msg_obj).encode("utf-8")
    sig = pk.sign(msg_bytes)
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    print(f"  [5] Signed PoP message ({len(sig)} bytes)")

    # 6. Register
    print(f"  [6] Submitting registration...")
    reg_resp = httpx.post(f"{gateway_url}/agents/register", json={
        "agent_id": config["agent_id"],
        "public_key": jwk,
        "proof": {
            "nonce": ch["nonce"],
            "challenge_id": ch["challenge_id"],
            "signature": sig_b64,
            "iat": iat,
        },
    }, timeout=15)

    if reg_resp.status_code != 200:
        print(f"  FAIL: registration returned {reg_resp.status_code}: {reg_resp.text}")
        sys.exit(1)

    result = reg_resp.json()
    print(f"      Result: {json.dumps(result)}")

    if not result.get("proof_of_possession_at_registration"):
        print(f"  FAIL: proof_of_possession_at_registration is not true")
        sys.exit(1)

    registry_kid = result.get("kid", "?")
    print(f"  [7] Verification:")
    print(f"      Registry kid: {registry_kid}")
    print(f"      Signing kid:  {signing_kid}")
    print(f"      Note: Different namespaces — registry uses 'agent-' prefix,")
    print(f"            signing uses '{name}-' prefix. Both derive from the same")
    print(f"            public key. PoP proves the registrant controls the private key.")

    print(f"\n  OK {name} registered with PoP (agent_id={config['agent_id']}, kid={registry_kid})")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--gateway-url", required=True)
    parser.add_argument("--project", default="quick-catcher-470218-b0")
    parser.add_argument("--agent", choices=list(SYSTEM_AGENTS.keys()))
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()

    if not args.agent and not args.all:
        print("Specify --agent=NAME or --all")
        sys.exit(1)

    targets = list(SYSTEM_AGENTS.keys()) if args.all else [args.agent]
    results = []

    for name in targets:
        r = bootstrap_agent(name, SYSTEM_AGENTS[name], args.project, args.tenant, args.gateway_url)
        results.append((name, r))

    print(f"\n{'='*60}")
    print(f"  Bootstrap complete: {len(results)}/{len(targets)} agents registered")
    print(f"{'='*60}")
    for name, r in results:
        print(f"  {name}: kid={r['kid']} pop={r.get('proof_of_possession_at_registration')}")


if __name__ == "__main__":
    main()
