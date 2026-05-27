"""Demo script — shows the Gateway in action without ADK/Gemini.

Run: python demo.py

This demonstrates the core authorization flow:
1. Agent requests authorization for a compliant action → APPROVE
2. Agent requests authorization for a blocked action → DENY
3. Agent exceeds rate limit → DENY
4. Show receipt chain with hash linkage
5. Show Merkle root
6. Show public key for independent verification
"""

import json

from gateway.gateway_service import GatewayService


def main():
    print("=" * 60)
    print("Agent Authorization Gateway — Demo")
    print("=" * 60)
    print()

    gateway = GatewayService(tenant="hackathon-demo")

    # Scenario 1: Compliant action (should APPROVE)
    print("--- Scenario 1: Read 10 records from staging database ---")
    r1 = gateway.authorize(
        agent_id="worker-analytics-01",
        action="read records",
        resource="staging-database",
        parameters={"limit": 10, "table": "analytics_events"},
    )
    print(f"Decision: {r1.decision.upper()}")
    print(f"Token issued: {'Yes (60s TTL)' if r1.token else 'No'}")
    print(f"Receipt hash: {r1.receipt_hash}")
    print()

    # Scenario 2: Blocked action (should DENY — production access)
    print("--- Scenario 2: Export all records from production database ---")
    r2 = gateway.authorize(
        agent_id="worker-analytics-01",
        action="export all customer records",
        resource="production-database",
        parameters={"limit": "unlimited"},
    )
    print(f"Decision: {r2.decision.upper()}")
    print(f"Reason codes: {r2.reason_codes}")
    print(f"Token issued: {'Yes' if r2.token else 'No (denied)'}")
    print(f"Receipt hash: {r2.receipt_hash}")
    print()

    # Scenario 3: Another compliant action
    print("--- Scenario 3: Search staging analytics ---")
    r3 = gateway.authorize(
        agent_id="worker-analytics-01",
        action="search analytics",
        resource="staging-analytics-api",
        parameters={"query": "conversion_rate > 0.05"},
    )
    print(f"Decision: {r3.decision.upper()}")
    print(f"Token issued: {'Yes (60s TTL)' if r3.token else 'No'}")
    print(f"Receipt hash: {r3.receipt_hash}")
    print()

    # Show receipt chain
    print("--- Receipt Chain (3 decisions) ---")
    chain = gateway.get_receipt_chain()
    for i, receipt in enumerate(chain):
        body = receipt["body"]
        print(f"  #{body['seq']}: {body['decision'].upper()} | "
              f"prev: ...{body['prev_receipt'][-12:]} | "
              f"hash: ...{receipt['receipt_hash'][-12:]}")
    print()

    # Show Merkle root
    stats = gateway.get_chain_stats()
    print("--- Chain Statistics ---")
    print(f"  Total receipts: {stats['total_receipts']}")
    print(f"  Approvals: {stats['approvals']}")
    print(f"  Denials: {stats['denials']}")
    print(f"  Merkle root: {stats['merkle_root']}")
    print(f"  Policy version: ...{stats['policy_version'][-16:]}")
    print()

    # Show public key
    jwk = gateway.get_public_key_jwk()
    print("--- Signing Public Key (JWK) ---")
    print(f"  Algorithm: {jwk['alg']}")
    print(f"  Key ID: {jwk['kid']}")
    print(f"  Public key (x): {jwk['x']}")
    print()

    print("Any auditor can verify this receipt chain independently")
    print("using the public key and the Receipt Chain Verification Protocol v0.1.")
    print()

    # Export full chain for verification
    export = {
        "receipts": chain,
        "keys": {"tenant": "hackathon-demo", "keys": [jwk]},
        "stats": stats,
    }
    with open("demo_output.json", "w") as f:
        json.dump(export, f, indent=2)
    print("Full chain exported to demo_output.json")


if __name__ == "__main__":
    main()
