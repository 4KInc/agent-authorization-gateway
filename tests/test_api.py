"""Integration tests for the Agent Authorization Gateway HTTP API.

Run with:
    pytest tests/test_api.py -v
"""

import base64
import os

# Disable Firestore before importing the app so the lifespan
# falls back to the in-memory store.
os.environ["FIRESTORE_ENABLED"] = ""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gateway.api import api_app, _get_gateway
from gateway.identity import create_agent_proof

client = TestClient(api_app)

# Pre-register an agent for all tests
_agent_key = Ed25519PrivateKey.generate()
_agent_id = "test-agent"


def _make_jwk(key):
    pub_bytes = key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


def _register_agent():
    """Register the test agent (idempotent)."""
    gw = _get_gateway()
    if gw._registry.get(_agent_id) is None:
        gw._registry.register(_agent_id, _make_jwk(_agent_key))


def _approve_payload() -> dict:
    """Return a valid authorize request that the demo policy will approve."""
    from gateway import identity
    identity._proof_jti_cache.clear()
    _register_agent()
    proof = create_agent_proof(_agent_key, _agent_id, "read", "staging-db")
    return {
        "agent_id": _agent_id,
        "action": "read",
        "resource": "staging-db",
        "agent_proof": proof,
    }


def _deny_payload() -> dict:
    """Return an authorize request that the demo policy will deny."""
    from gateway import identity
    identity._proof_jti_cache.clear()
    _register_agent()
    proof = create_agent_proof(_agent_key, _agent_id, "delete", "production-db")
    return {
        "agent_id": _agent_id,
        "action": "delete",
        "resource": "production-db",
        "agent_proof": proof,
    }


# ---------------------------------------------------------------------------
# 1. GET / — redirects to /docs
# ---------------------------------------------------------------------------

def test_root_redirects_to_docs():
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 307
    assert resp.headers["location"] == "/docs"


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
    assert data["token"] is not None
    assert isinstance(data["token"], str) and len(data["token"]) > 0

    receipt = data["receipt"]
    assert "body" in receipt
    assert "sig" in receipt
    assert "receipt_hash" in receipt
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
    assert data["token"] is None
    assert len(data["reason_codes"]) > 0
    reason_text = " ".join(data["reason_codes"])
    assert "ACTION_NOT_ALLOWED" in reason_text or "RESOURCE_OUT_OF_SCOPE" in reason_text

    receipt = data["receipt"]
    assert "body" in receipt
    assert "sig" in receipt
    assert "receipt_hash" in receipt


# ---------------------------------------------------------------------------
# 5. POST /authorize — missing required fields returns 422
# ---------------------------------------------------------------------------

def test_authorize_missing_fields_returns_422():
    # Missing agent_proof (now required)
    resp = client.post("/authorize", json={"agent_id": "test-agent", "action": "read", "resource": "db"})
    assert resp.status_code == 422

    # Completely empty body
    resp2 = client.post("/authorize", json={})
    assert resp2.status_code == 422


# ---------------------------------------------------------------------------
# 6. POST /verify-receipt — valid receipt passes integrity check
# ---------------------------------------------------------------------------

def test_verify_receipt_passes():
    auth_resp = client.post("/authorize", json=_approve_payload())
    receipt = auth_resp.json()["receipt"]
    resp = client.post("/verify-receipt", json={"receipt": receipt})
    assert resp.status_code == 200
    data = resp.json()
    assert data["receipt_integrity"] == "PASS"


# ---------------------------------------------------------------------------
# 7. POST /verify-chain — multiple receipts pass chain validation
# ---------------------------------------------------------------------------

def test_verify_chain_passes():
    client.post("/authorize", json=_approve_payload())
    client.post("/authorize", json=_approve_payload())

    chain_resp = client.get("/chain")
    receipts = chain_resp.json()["receipts"]

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
    assert isinstance(jwk["x"], str) and len(jwk["x"]) > 0


# ---------------------------------------------------------------------------
# 11. POST /authorize/dry-run — approve scenario
# ---------------------------------------------------------------------------

def test_authorize_dry_run_approve():
    resp = client.post("/authorize/dry-run", json={
        "agent_id": "agent-1",
        "action": "read",
        "resource": "staging-db",
        "agent_proof": "dummy-not-checked-in-dry-run",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "approve"
    assert data["dry_run"] is True
    assert "token" not in data


# ---------------------------------------------------------------------------
# 12. POST /authorize/dry-run — deny scenario
# ---------------------------------------------------------------------------

def test_authorize_dry_run_deny():
    resp = client.post("/authorize/dry-run", json={
        "agent_id": "rogue",
        "action": "delete",
        "resource": "production-db",
        "agent_proof": "dummy-not-checked-in-dry-run",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "deny"
    assert len(data["reason_codes"]) > 0
    assert data["dry_run"] is True


# ---------------------------------------------------------------------------
# 13. POST /authorize/dry-run does not create a receipt
# ---------------------------------------------------------------------------

def test_dry_run_does_not_create_receipt():
    before = client.get("/stats").json()["total_receipts"]
    client.post("/authorize/dry-run", json={
        "agent_id": "agent-1",
        "action": "read",
        "resource": "staging-db",
        "agent_proof": "dummy",
    })
    after = client.get("/stats").json()["total_receipts"]
    assert after == before


# ---------------------------------------------------------------------------
# 14. GET /policy — returns rules, hash, and tenant
# ---------------------------------------------------------------------------

def test_get_policy():
    resp = client.get("/policy")
    assert resp.status_code == 200
    data = resp.json()
    assert "tenant" in data
    assert isinstance(data["rules"], list)
    assert len(data["rules"]) == 3
    assert data["policy_hash"].startswith("sha256:")


# ---------------------------------------------------------------------------
# 15. PUT /policy — update and verify effect
# ---------------------------------------------------------------------------

def test_update_policy():
    original = client.get("/policy").json()

    new_rules = [
        {"id": "allowed_actions", "type": "allowlist", "config": {"allowed_actions": ["read"]}},
        {"id": "resource_scope", "type": "resource_scope", "config": {
            "allowed_resources": ["staging", "dev", "sandbox", "test"],
            "denied_resources": ["production", "prod"],
        }},
        {"id": "rate_limit", "type": "rate_limit", "config": {"max_actions": 100, "window_seconds": 60}},
    ]
    update_resp = client.put("/policy", json={"version": "2", "rules": new_rules})
    assert update_resp.status_code == 200
    assert update_resp.json()["status"] == "updated"

    # "query" was previously allowed but should now be denied
    _register_agent()
    proof = create_agent_proof(_agent_key, _agent_id, "query", "staging-db")
    auth_resp = client.post("/authorize", json={
        "agent_id": _agent_id,
        "action": "query",
        "resource": "staging-db",
        "agent_proof": proof,
    })
    assert auth_resp.json()["decision"] == "deny"

    # Restore original policy
    restore_resp = client.put("/policy", json={
        "version": original["version"],
        "rules": original["rules"],
    })
    assert restore_resp.status_code == 200


# ---------------------------------------------------------------------------
# 16. POST /authorize — validation: whitespace-only agent_id → 422
# ---------------------------------------------------------------------------

def test_authorize_validation_empty_agent_id():
    resp = client.post("/authorize", json={
        "agent_id": "   ",
        "action": "read",
        "resource": "staging-db",
        "agent_proof": "dummy",
    })
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 17. POST /authorize — validation: empty action → 422
# ---------------------------------------------------------------------------

def test_authorize_validation_empty_action():
    resp = client.post("/authorize", json={
        "agent_id": "test-agent",
        "action": "",
        "resource": "staging-db",
        "agent_proof": "dummy",
    })
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 18. Resource endpoints
# ---------------------------------------------------------------------------

def test_resource_register():
    resp = client.post("/resources/register", json={
        "resource_id": "test-api-resource",
        "display_name": "Test API Resource",
        "description": "Created by test_api.py",
        "resource_type": "db",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "registered"
    assert data["resource_id"] == "test-api-resource"


def test_resource_register_duplicate_409():
    client.post("/resources/register", json={
        "resource_id": "dup-resource",
        "display_name": "Dup Resource",
        "resource_type": "db",
    })
    resp = client.post("/resources/register", json={
        "resource_id": "dup-resource",
        "display_name": "Dup Resource",
        "resource_type": "db",
    })
    assert resp.status_code == 409


def test_resource_register_invalid_id_400():
    resp = client.post("/resources/register", json={
        "resource_id": "bad id!",
        "display_name": "Bad",
        "resource_type": "db",
    })
    assert resp.status_code == 400


def test_resource_register_rejects_invalid_type():
    resp = client.post("/resources/register", json={
        "resource_id": "test-invalid-type",
        "display_name": "Test",
        "resource_type": "spaceship",
    })
    assert resp.status_code == 422


def test_resource_register_rejects_missing_type():
    resp = client.post("/resources/register", json={
        "resource_id": "test-no-type",
        "display_name": "Test",
    })
    assert resp.status_code == 422


def test_resource_list():
    client.post("/resources/register", json={
        "resource_id": "list-test-resource",
        "display_name": "List Test",
        "resource_type": "db",
    })
    resp = client.get("/resources")
    assert resp.status_code == 200
    data = resp.json()
    assert "resources" in data
    assert "count" in data
    ids = [r["resource_id"] for r in data["resources"]]
    assert "list-test-resource" in ids


def test_resource_get():
    client.post("/resources/register", json={
        "resource_id": "get-test-resource",
        "display_name": "Get Test",
        "resource_type": "db",
    })
    resp = client.get("/resources/get-test-resource")
    assert resp.status_code == 200
    data = resp.json()
    assert data["resource_id"] == "get-test-resource"
    assert data["status"] == "active"


def test_resource_get_404():
    resp = client.get("/resources/nonexistent-resource")
    assert resp.status_code == 404


def test_resource_revoke():
    client.post("/resources/register", json={
        "resource_id": "revoke-test-resource",
        "display_name": "Revoke Test",
        "resource_type": "db",
    })
    resp = client.delete("/resources/revoke-test-resource")
    assert resp.status_code == 200
    assert resp.json()["status"] == "revoked"

    get_resp = client.get("/resources/revoke-test-resource")
    assert get_resp.json()["status"] == "revoked"


def test_resource_revoke_404():
    resp = client.delete("/resources/nonexistent-resource")
    assert resp.status_code == 404


def test_resource_update():
    client.post("/resources/register", json={
        "resource_id": "update-test-resource",
        "display_name": "Update Test",
        "resource_type": "db",
    })
    resp = client.patch("/resources/update-test-resource", json={
        "display_name": "Updated Name",
        "description": "Updated desc",
        "owner": "new-owner",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["display_name"] == "Updated Name"
    assert data["description"] == "Updated desc"
    assert data["version"] == 2


def test_resource_hierarchical_id():
    """Test resource IDs with dots and slashes (hierarchical)."""
    resp = client.post("/resources/register", json={
        "resource_id": "gcp.cloudsql.staging/customers",
        "display_name": "GCP Staging Customers",
        "resource_type": "db",
    })
    assert resp.status_code == 200

    get_resp = client.get("/resources/gcp.cloudsql.staging/customers")
    assert get_resp.status_code == 200
    assert get_resp.json()["resource_id"] == "gcp.cloudsql.staging/customers"
