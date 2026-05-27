"""Integration tests for the Agent Authorization Gateway HTTP API.

Run with:
    pytest tests/test_api.py -v
"""

import os

# Disable Firestore before importing the app so the lifespan
# falls back to the in-memory store.
os.environ["FIRESTORE_ENABLED"] = ""

from fastapi.testclient import TestClient

from gateway.api import api_app

client = TestClient(api_app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _approve_payload() -> dict:
    """Return a valid authorize request that the demo policy will approve."""
    return {
        "agent_id": "test-agent",
        "action": "read",
        "resource": "staging-db",
    }


def _deny_payload() -> dict:
    """Return an authorize request that the demo policy will deny.

    'delete' is not in the allowlist and 'production' is a denied resource,
    so the request triggers two deny reasons.
    """
    return {
        "agent_id": "test-agent",
        "action": "delete",
        "resource": "production-db",
    }


# ---------------------------------------------------------------------------
# 1. GET / — HTML dashboard
# ---------------------------------------------------------------------------

def test_root_returns_html_dashboard():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    # Sanity-check that it looks like HTML
    assert "<html" in resp.text.lower() or "<!doctype" in resp.text.lower()


# ---------------------------------------------------------------------------
# 2. GET /health — health check
# ---------------------------------------------------------------------------

def test_health_returns_healthy():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "tenant" in data
    assert data["provider"] == "agent-authorization-gateway"


# ---------------------------------------------------------------------------
# 3. POST /authorize — approve scenario
# ---------------------------------------------------------------------------

def test_authorize_approve():
    resp = client.post("/authorize", json=_approve_payload())
    assert resp.status_code == 200
    data = resp.json()

    assert data["decision"] == "approve"
    assert data["reason_codes"] == []

    # Approved requests must include a token
    assert data["token"] is not None
    assert isinstance(data["token"], str) and len(data["token"]) > 0

    # Receipt envelope must exist with body, sig, and receipt_hash
    receipt = data["receipt"]
    assert "body" in receipt
    assert "sig" in receipt
    assert "receipt_hash" in receipt

    # action_digest and receipt_hash are hex-ish strings
    assert isinstance(data["action_digest"], str) and len(data["action_digest"]) > 0
    assert isinstance(data["receipt_hash"], str) and len(data["receipt_hash"]) > 0


# ---------------------------------------------------------------------------
# 4. POST /authorize — deny scenario
# ---------------------------------------------------------------------------

def test_authorize_deny():
    resp = client.post("/authorize", json=_deny_payload())
    assert resp.status_code == 200
    data = resp.json()

    assert data["decision"] == "deny"

    # Denied requests must NOT include a token
    assert data["token"] is None

    # There should be reason codes explaining the denial
    assert len(data["reason_codes"]) > 0
    reason_text = " ".join(data["reason_codes"])
    assert "ACTION_NOT_ALLOWED" in reason_text or "RESOURCE_OUT_OF_SCOPE" in reason_text

    # Receipt should still be present (every decision is receipted)
    receipt = data["receipt"]
    assert "body" in receipt
    assert "sig" in receipt
    assert "receipt_hash" in receipt


# ---------------------------------------------------------------------------
# 5. POST /authorize — missing required fields returns 422
# ---------------------------------------------------------------------------

def test_authorize_missing_fields_returns_422():
    # Missing 'action' and 'resource'
    resp = client.post("/authorize", json={"agent_id": "test-agent"})
    assert resp.status_code == 422

    # Completely empty body
    resp2 = client.post("/authorize", json={})
    assert resp2.status_code == 422


# ---------------------------------------------------------------------------
# 6. POST /verify-receipt — valid receipt passes integrity check
# ---------------------------------------------------------------------------

def test_verify_receipt_passes():
    # First, create a receipt via /authorize
    auth_resp = client.post("/authorize", json=_approve_payload())
    receipt = auth_resp.json()["receipt"]

    # Now verify it
    resp = client.post("/verify-receipt", json={"receipt": receipt})
    assert resp.status_code == 200
    data = resp.json()
    assert data["receipt_integrity"] == "PASS"


# ---------------------------------------------------------------------------
# 7. POST /verify-chain — multiple receipts pass chain validation
# ---------------------------------------------------------------------------

def test_verify_chain_passes():
    # We need a fresh chain, but the module-level gateway persists.
    # Issue two authorize calls and grab the full chain from /chain.
    client.post("/authorize", json=_approve_payload())
    client.post("/authorize", json=_approve_payload())

    chain_resp = client.get("/chain")
    receipts = chain_resp.json()["receipts"]

    # Verify the entire chain
    resp = client.post("/verify-chain", json={"receipts": receipts})
    assert resp.status_code == 200
    data = resp.json()
    assert data["chain_validity"] == "PASS"
    assert data["receipt_integrity"] == "PASS"
    assert data["errors"] == []


# ---------------------------------------------------------------------------
# 8. GET /chain — returns receipts list
# ---------------------------------------------------------------------------

def test_chain_returns_receipts():
    resp = client.get("/chain")
    assert resp.status_code == 200
    data = resp.json()

    assert "tenant" in data
    assert "receipts" in data
    assert isinstance(data["receipts"], list)
    assert "count" in data
    assert data["count"] == len(data["receipts"])


# ---------------------------------------------------------------------------
# 9. GET /stats — returns correct counts after authorize calls
# ---------------------------------------------------------------------------

def test_stats_returns_counts():
    # Issue one approve and one deny to ensure both counters increment
    client.post("/authorize", json=_approve_payload())
    client.post("/authorize", json=_deny_payload())

    resp = client.get("/stats")
    assert resp.status_code == 200
    data = resp.json()

    assert "tenant" in data
    assert isinstance(data["total_receipts"], int)
    assert data["total_receipts"] > 0
    assert isinstance(data["approvals"], int)
    assert data["approvals"] > 0
    assert isinstance(data["denials"], int)
    assert data["denials"] > 0
    assert "policy_version" in data
    # merkle_root should be present once there are receipts
    assert data["merkle_root"] is not None


# ---------------------------------------------------------------------------
# 10. GET /keys — returns Ed25519 JWK with correct fields
# ---------------------------------------------------------------------------

def test_keys_returns_ed25519_jwk():
    resp = client.get("/keys")
    assert resp.status_code == 200
    data = resp.json()

    assert "tenant" in data
    assert "keys" in data
    assert isinstance(data["keys"], list)
    assert len(data["keys"]) >= 1

    jwk = data["keys"][0]
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert jwk["alg"] == "EdDSA"
    assert jwk["use"] == "sig"
    assert "kid" in jwk
    assert "x" in jwk
    # x should be a base64url-encoded 32-byte Ed25519 public key
    assert isinstance(jwk["x"], str) and len(jwk["x"]) > 0
