#!/usr/bin/env python3
"""Demo: Tamper Detection — proves the chain catches modifications.

This demo:
1. Creates several authorization decisions to build a chain
2. Verifies the chain passes
3. Tampers with a receipt via /tamper-test
4. Verifies the chain now FAILS at the exact tampered receipt
"""

import json
import os
import sys

import httpx

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8080")


def run():
    print("=" * 60)
    print("  TAMPER DETECTION DEMO")
    print("=" * 60)

    with httpx.Client(timeout=15) as client:
        # Step 1: Build a chain
        print(f"\n[1] Building a receipt chain (5 decisions)...")
        actions = [
            ("agent-1", "read", "staging-db"),
            ("agent-2", "query", "staging-analytics"),
            ("agent-1", "list", "dev-datasets"),
            ("agent-3", "search", "sandbox-logs"),
            ("agent-1", "delete", "production-db"),  # will be denied
        ]
        for agent, action, resource in actions:
            resp = client.post(f"{GATEWAY_URL}/authorize", json={
                "agent_id": agent, "action": action, "resource": resource,
            })
            d = resp.json()
            print(f"    {agent} → {action} on {resource}: {d['decision']}")

        # Step 2: Verify chain (should pass)
        print(f"\n[2] Verifying chain before tampering...")
        chain_resp = client.get(f"{GATEWAY_URL}/chain")
        chain = chain_resp.json()
        print(f"    Chain has {chain['count']} receipts")

        verify_resp = client.post(f"{GATEWAY_URL}/verify-chain", json={
            "receipts": chain["receipts"],
        })
        v = verify_resp.json()
        print(f"    Integrity: {v['receipt_integrity']}")
        print(f"    Chain:     {v['chain_validity']}")
        print(f"    Errors:    {len(v['errors'])}")

        if v["receipt_integrity"] != "PASS":
            print("    WARNING: Chain already has integrity issues. Skipping tamper test.")
            return 1

        # Step 3: Tamper with receipt #2
        print(f"\n[3] Tampering with receipt at index 2 (field: decision)...")
        tamper_resp = client.post(f"{GATEWAY_URL}/tamper-test", params={
            "receipt_index": 2,
            "field": "decision",
        })
        if tamper_resp.status_code == 403:
            print("    GATEWAY_DEV_MODE not enabled. Set GATEWAY_DEV_MODE=true to run this demo.")
            return 1
        t = tamper_resp.json()
        print(f"    Original value: {t.get('original_value')}")
        print(f"    Tampered value: {t.get('new_value')}")

        # Step 4: Re-verify chain (should FAIL)
        print(f"\n[4] Re-verifying chain after tampering...")
        chain_resp = client.get(f"{GATEWAY_URL}/chain")
        chain = chain_resp.json()
        verify_resp = client.post(f"{GATEWAY_URL}/verify-chain", json={
            "receipts": chain["receipts"],
        })
        v = verify_resp.json()
        print(f"    Integrity: {v['receipt_integrity']}")
        print(f"    Chain:     {v['chain_validity']}")
        if v["errors"]:
            for err in v["errors"]:
                print(f"    Error: [{err.get('code')}] {err.get('message', '')[:80]}")

        detected = v["receipt_integrity"] == "FAIL" or v["chain_validity"] == "FAIL"
        print(f"\n{'=' * 60}")
        print(f"  TAMPER {'DETECTED' if detected else 'NOT DETECTED — THIS IS A BUG'}")
        print(f"{'=' * 60}")

        return 0 if detected else 1


if __name__ == "__main__":
    sys.exit(run())
