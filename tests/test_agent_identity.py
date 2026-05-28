"""Tests for agent identity verification (Phase 3).

Verifies DPoP-style proof of possession: agents must prove they
hold their private key before the Gateway authorizes actions.
"""

import base64
import os
import time

os.environ["FIRESTORE_ENABLED"] = ""

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway.identity import (
    AgentRegistry,
    create_agent_proof,
    verify_agent_proof,
)


def _make_jwk(private_key: Ed25519PrivateKey) -> dict:
    """Create a JWK from a private key (public part only)."""
    pub_bytes = private_key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


class TestAgentRegistration:
    def test_register_agent(self):
        registry = AgentRegistry()
        key = Ed25519PrivateKey.generate()
        jwk = _make_jwk(key)
        agent = registry.register("agent-1", jwk)
        assert agent.agent_id == "agent-1"
        assert agent.kid.startswith("agent-")

    def test_lookup_registered_agent(self):
        registry = AgentRegistry()
        key = Ed25519PrivateKey.generate()
        agent = registry.register("agent-1", _make_jwk(key))
        found = registry.get("agent-1")
        assert found is not None
        assert found.kid == agent.kid

    def test_unregistered_agent_returns_none(self):
        registry = AgentRegistry()
        assert registry.get("nonexistent") is None

    def test_list_agents(self):
        registry = AgentRegistry()
        for i in range(3):
            registry.register(f"agent-{i}", _make_jwk(Ed25519PrivateKey.generate()))
        agents = registry.list_agents()
        assert len(agents) == 3


class TestAgentProof:
    def setup_method(self):
        self.registry = AgentRegistry()
        self.key = Ed25519PrivateKey.generate()
        self.registry.register("agent-1", _make_jwk(self.key))
        # Reset JTI cache between tests
        from gateway import identity
        identity._proof_jti_cache.clear()

    def test_valid_proof_succeeds(self):
        proof = create_agent_proof(self.key, "agent-1", "read", "staging-db")
        agent = verify_agent_proof(proof, self.registry, "agent-1", "read", "staging-db")
        assert agent.agent_id == "agent-1"

    def test_unregistered_agent_rejected(self):
        key2 = Ed25519PrivateKey.generate()
        proof = create_agent_proof(key2, "unknown-agent", "read", "db")
        with pytest.raises(ValueError, match="UNREGISTERED_AGENT"):
            verify_agent_proof(proof, self.registry, "unknown-agent", "read", "db")

    def test_wrong_key_rejected(self):
        """Agent registered with key A, proof signed with key B."""
        wrong_key = Ed25519PrivateKey.generate()
        proof = create_agent_proof(wrong_key, "agent-1", "read", "db")
        with pytest.raises(ValueError, match="INVALID_PROOF_SIGNATURE"):
            verify_agent_proof(proof, self.registry, "agent-1", "read", "db")

    def test_agent_id_mismatch_rejected(self):
        """Proof says sub=agent-1 but expected agent-2."""
        proof = create_agent_proof(self.key, "agent-1", "read", "db")
        with pytest.raises(ValueError, match="AGENT_MISMATCH"):
            verify_agent_proof(proof, self.registry, "agent-2", "read", "db")

    def test_wrong_action_rejected(self):
        """Proof bound to action=read but endpoint expects action=write."""
        proof = create_agent_proof(self.key, "agent-1", "read", "db")
        with pytest.raises(ValueError, match="PROOF_ACTION_MISMATCH"):
            verify_agent_proof(proof, self.registry, "agent-1", "write", "db")

    def test_wrong_resource_rejected(self):
        """Proof bound to resource=staging but endpoint expects resource=production."""
        proof = create_agent_proof(self.key, "agent-1", "read", "staging")
        with pytest.raises(ValueError, match="PROOF_RESOURCE_MISMATCH"):
            verify_agent_proof(proof, self.registry, "agent-1", "read", "production")

    def test_replayed_proof_rejected(self):
        """Same proof used twice → second use is rejected."""
        proof = create_agent_proof(self.key, "agent-1", "read", "staging-db")
        # First use succeeds
        verify_agent_proof(proof, self.registry, "agent-1", "read", "staging-db")
        # Second use fails
        with pytest.raises(ValueError, match="PROOF_REPLAY"):
            verify_agent_proof(proof, self.registry, "agent-1", "read", "staging-db")

    def test_expired_proof_rejected(self):
        """Proof created >30 seconds ago → rejected."""
        # Create a proof with iat in the past
        now = time.time()
        payload = {
            "sub": "agent-1",
            "htm": "POST",
            "htu": "gateway",
            "action": "read",
            "resource": "db",
            "jti": "expired-proof-jti",
            "iat": int(now - 60),  # 60 seconds ago
        }
        proof = pyjwt.encode(payload, self.key, algorithm="EdDSA")
        with pytest.raises(ValueError, match="PROOF_EXPIRED"):
            verify_agent_proof(proof, self.registry, "agent-1", "read", "db")


class TestAgentIdentityAPI:
    """Test the API endpoints for agent registration and proof."""

    def test_register_and_authorize_with_proof(self):
        from fastapi.testclient import TestClient
        from gateway.api import api_app

        client = TestClient(api_app)

        # Generate agent keypair
        agent_key = Ed25519PrivateKey.generate()
        jwk = _make_jwk(agent_key)

        # Register agent
        resp = client.post("/agents/register", json={
            "agent_id": "test-agent-api",
            "public_key": jwk,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "registered"
        assert data["agent_id"] == "test-agent-api"

        # Create proof and authorize
        proof = create_agent_proof(agent_key, "test-agent-api", "read", "staging-db")
        resp = client.post("/authorize", json={
            "agent_id": "test-agent-api",
            "action": "read",
            "resource": "staging-db",
            "agent_proof": proof,
        })
        assert resp.status_code == 200
        assert resp.json()["decision"] == "approve"

    def test_authorize_with_invalid_proof_rejected(self):
        from fastapi.testclient import TestClient
        from gateway.api import api_app

        client = TestClient(api_app)

        # Try to authorize with a proof from an unregistered agent
        rogue_key = Ed25519PrivateKey.generate()
        proof = create_agent_proof(rogue_key, "rogue-agent", "read", "staging-db")
        resp = client.post("/authorize", json={
            "agent_id": "rogue-agent",
            "action": "read",
            "resource": "staging-db",
            "agent_proof": proof,
        })
        assert resp.status_code == 401

    def test_list_agents(self):
        from fastapi.testclient import TestClient
        from gateway.api import api_app

        client = TestClient(api_app)
        resp = client.get("/agents")
        assert resp.status_code == 200
        assert "agents" in resp.json()
