#!/usr/bin/env python3
"""Generate realistic enterprise demo data across the deployed gateway.

Registers 7 scenario agents, issues ~90 authorize_action requests across
three phases (baseline, borderline, incident), then triggers the Auditor
to produce audit reports.

Usage:
    python demo/generate_demo_data.py
"""

import base64
import json
import os
import random
import sys
import time

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gateway.identity import create_agent_proof

GATEWAY_URL = os.environ.get("GATEWAY_URL", "https://agent-auth-gateway-1031148889398.us-central1.run.app")
AUDITOR_URL = os.environ.get("AUDITOR_URL", "https://agent-auth-gateway-auditor-lwmxdereeq-uc.a.run.app")

# --- Agent definitions ---
AGENTS = {
    "claude-cs-prod-01": {"role": "Customer service agent"},
    "claude-cs-prod-02": {"role": "Customer service agent"},
    "gemini-analyst-prod": {"role": "Financial analyst agent"},
    "crewai-marketing-01": {"role": "Marketing content agent"},
    "claude-ops-prod-01": {"role": "DevOps agent"},
    "claude-marketing-04": {"role": "Marketing agent (compromised in scenario)"},
    "langchain-research-02": {"role": "Research agent"},
}

# Store keypairs
agent_keys: dict[str, Ed25519PrivateKey] = {}


def make_jwk(key: Ed25519PrivateKey) -> dict:
    pub = key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(pub).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


def register_agents(client: httpx.Client):
    print("=== Registering 7 scenario agents ===")
    for agent_id in AGENTS:
        key = Ed25519PrivateKey.generate()
        agent_keys[agent_id] = key
        jwk = make_jwk(key)
        resp = client.post(f"{GATEWAY_URL}/agents/register", json={
            "agent_id": agent_id,
            "public_key": jwk,
        })
        status = "OK" if resp.status_code == 200 else f"FAIL ({resp.status_code})"
        print(f"  {agent_id}: {status}")


def authorize(client: httpx.Client, agent_id: str, action: str, resource: str) -> dict:
    key = agent_keys[agent_id]
    proof = create_agent_proof(key, agent_id, action, resource)
    resp = client.post(f"{GATEWAY_URL}/authorize", json={
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "agent_proof": proof,
    })
    if resp.status_code == 200:
        data = resp.json()
        return {"decision": data.get("decision"), "reason_codes": data.get("reason_codes", [])}
    elif resp.status_code == 401:
        return {"decision": "identity_error", "detail": resp.json().get("detail", "")}
    else:
        return {"decision": "error", "status": resp.status_code}


def phase_a(client: httpx.Client):
    """Baseline: 50 legitimate requests across 5 well-behaved agents."""
    print("\n=== Phase A: Baseline activity (50 requests) ===")
    requests = [
        # Customer service agents reading account data
        ("claude-cs-prod-01", "read", "staging-customer-accounts"),
        ("claude-cs-prod-01", "query", "staging-customer-accounts"),
        ("claude-cs-prod-01", "read", "staging-transaction-history"),
        ("claude-cs-prod-01", "search", "staging-knowledge-base"),
        ("claude-cs-prod-01", "read", "staging-customer-accounts"),
        ("claude-cs-prod-01", "query", "staging-transaction-history"),
        ("claude-cs-prod-01", "read", "staging-knowledge-base"),
        ("claude-cs-prod-01", "search", "staging-customer-accounts"),
        ("claude-cs-prod-02", "read", "staging-customer-accounts"),
        ("claude-cs-prod-02", "query", "staging-customer-accounts"),
        ("claude-cs-prod-02", "read", "staging-transaction-history"),
        ("claude-cs-prod-02", "search", "staging-knowledge-base"),
        ("claude-cs-prod-02", "read", "staging-customer-accounts"),
        ("claude-cs-prod-02", "query", "staging-transaction-history"),
        ("claude-cs-prod-02", "read", "staging-knowledge-base"),
        ("claude-cs-prod-02", "search", "staging-customer-accounts"),
        # Financial analyst
        ("gemini-analyst-prod", "read", "staging-financial-models"),
        ("gemini-analyst-prod", "analyze", "staging-financial-models"),
        ("gemini-analyst-prod", "read", "staging-transaction-history"),
        ("gemini-analyst-prod", "query", "staging-financial-models"),
        ("gemini-analyst-prod", "analyze", "staging-risk-metrics"),
        ("gemini-analyst-prod", "read", "staging-market-data"),
        ("gemini-analyst-prod", "query", "staging-risk-metrics"),
        ("gemini-analyst-prod", "analyze", "staging-portfolio-data"),
        ("gemini-analyst-prod", "read", "staging-compliance-reports"),
        ("gemini-analyst-prod", "query", "staging-market-data"),
        # DevOps agent
        ("claude-ops-prod-01", "read", "staging-infrastructure-logs"),
        ("claude-ops-prod-01", "query", "staging-deployment-status"),
        ("claude-ops-prod-01", "read", "staging-monitoring-data"),
        ("claude-ops-prod-01", "analyze", "staging-performance-metrics"),
        ("claude-ops-prod-01", "read", "staging-config-store"),
        ("claude-ops-prod-01", "query", "staging-infrastructure-logs"),
        ("claude-ops-prod-01", "read", "staging-deployment-status"),
        ("claude-ops-prod-01", "analyze", "staging-monitoring-data"),
        # Research agent
        ("langchain-research-02", "read", "staging-compliance-docs"),
        ("langchain-research-02", "search", "staging-compliance-docs"),
        ("langchain-research-02", "read", "staging-knowledge-base"),
        ("langchain-research-02", "query", "staging-regulatory-filings"),
        ("langchain-research-02", "read", "staging-compliance-docs"),
        ("langchain-research-02", "search", "staging-knowledge-base"),
        ("langchain-research-02", "read", "staging-regulatory-filings"),
        ("langchain-research-02", "query", "staging-compliance-docs"),
        # Extra baseline from various agents
        ("claude-cs-prod-01", "read", "staging-customer-accounts"),
        ("claude-cs-prod-02", "query", "staging-knowledge-base"),
        ("gemini-analyst-prod", "read", "staging-financial-models"),
        ("claude-ops-prod-01", "read", "staging-config-store"),
        ("langchain-research-02", "search", "staging-compliance-docs"),
        ("claude-cs-prod-01", "query", "staging-transaction-history"),
        ("gemini-analyst-prod", "analyze", "staging-risk-metrics"),
        ("claude-ops-prod-01", "query", "staging-monitoring-data"),
    ]

    approve = deny = 0
    for agent_id, action, resource in requests:
        result = authorize(client, agent_id, action, resource)
        if result["decision"] == "approve":
            approve += 1
        else:
            deny += 1
        time.sleep(random.uniform(0.3, 0.8))

    print(f"  Phase A: {approve} approved, {deny} denied")


def phase_b(client: httpx.Client):
    """Borderline: marketing agent with PII access attempts."""
    print("\n=== Phase B: Borderline pattern (23 requests) ===")

    approve = deny = 0
    # 18 legitimate marketing requests
    for i in range(18):
        action = random.choice(["read", "search", "list"])
        resource = random.choice(["staging-marketing-content", "staging-knowledge-base", "dev-content-store"])
        result = authorize(client, "crewai-marketing-01", action, resource)
        if result["decision"] == "approve":
            approve += 1
        else:
            deny += 1
        time.sleep(random.uniform(0.2, 0.5))

    # 5 PII/scope violation attempts (will be denied)
    for i in range(5):
        action = random.choice(["read", "query"])
        resource = random.choice(["production-customer-pii", "production-customer-database", "admin-user-records"])
        result = authorize(client, "crewai-marketing-01", action, resource)
        if result["decision"] == "approve":
            approve += 1
        else:
            deny += 1
        print(f"    PII attempt {i+1}: {result['decision']} {result.get('reason_codes', [])}")
        time.sleep(random.uniform(0.2, 0.4))

    print(f"  Phase B: {approve} approved, {deny} denied")


def phase_c(client: httpx.Client):
    """Critical incident: compromised agent rapid delete attempts."""
    print("\n=== Phase C: Critical incident (31 requests) ===")

    approve = deny = error = 0
    # 3 legitimate baseline requests
    for i in range(3):
        result = authorize(client, "claude-marketing-04", "read", "staging-marketing-content")
        if result["decision"] == "approve":
            approve += 1
        else:
            deny += 1
        time.sleep(0.3)

    # 28 rapid anomalous delete attempts on production
    for i in range(28):
        result = authorize(client, "claude-marketing-04", "delete", "production-customer-database")
        d = result["decision"]
        if d == "approve":
            approve += 1
        elif d == "deny":
            deny += 1
        else:
            error += 1
        if i < 3 or i % 10 == 0:
            print(f"    Delete attempt {i+1}: {d} {result.get('reason_codes', result.get('detail', ''))}")
        time.sleep(random.uniform(0.1, 0.3))

    print(f"  Phase C: {approve} approved, {deny} denied, {error} errors")


def trigger_auditor():
    """Trigger the auditor to process new receipts."""
    print("\n=== Triggering Auditor ===")
    try:
        resp = httpx.post(f"{AUDITOR_URL}/audit-tick", timeout=300)
        data = resp.json()
        print(f"  Audited: {data.get('audited', 0)}")
        print(f"  Verdicts: {data.get('by_verdict', {})}")
    except Exception as e:
        print(f"  Auditor trigger failed: {e}")


def main():
    print("Gate Multi-Agent Demo Data Generator")
    print("=" * 50)

    with httpx.Client(timeout=30) as client:
        register_agents(client)
        phase_a(client)
        phase_b(client)
        phase_c(client)

    # Check final chain state
    resp = httpx.get(f"{GATEWAY_URL}/chain", timeout=15)
    chain = resp.json()
    print(f"\n=== Final state ===")
    print(f"  Total receipts: {chain.get('count', '?')}")

    trigger_auditor()

    print("\n=== Done ===")
    print("Dashboard: https://agent-auth-demo-ui-1031148889398.us-central1.run.app/dashboard")


if __name__ == "__main__":
    main()
