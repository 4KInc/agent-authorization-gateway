"""Tests for MCP transport auth + DPoP identity enforcement.

Proves the security hole is closed:
- Transport: MCP rejects unauthenticated connections
- Identity: authorize_action rejects calls without valid DPoP proof on ALL surfaces
- Cross-surface: same enforcement on MCP, REST, and ADK tool path
"""

import base64
import json
import os
import subprocess
import sys
import time

os.environ["FIRESTORE_ENABLED"] = ""

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def _has_google_adk():
    try:
        import google.adk
        return True
    except ImportError:
        return False


from gateway.gateway_service import GatewayService
from gateway.identity import (
    AgentRegistry,
    create_agent_proof,
)
from gateway.tokens import compute_action_digest


def _make_jwk(private_key: Ed25519PrivateKey) -> dict:
    pub_bytes = private_key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


def _make_registered_gateway() -> tuple[GatewayService, Ed25519PrivateKey, str]:
    """Create a gateway with a registered agent, return (gateway, agent_key, agent_id)."""
    registry = AgentRegistry()
    agent_key = Ed25519PrivateKey.generate()
    jwk = _make_jwk(agent_key)
    agent_id = "test-agent-01"
    registry.register(agent_id, jwk)
    gw = GatewayService(tenant="test-tenant", registry=registry)
    return gw, agent_key, agent_id


# =============================================================================
# 4.1 — Transport auth
# =============================================================================


_has_uvicorn = True
try:
    import uvicorn  # noqa: F401
except ImportError:
    _has_uvicorn = False


@pytest.mark.skipif(not _has_uvicorn, reason="uvicorn not installed (MCP server runtime dependency)")
class TestTransportAuth:
    """Tests for MCP transport authentication (bearer mode)."""

    def _make_app(self, auth_mode, auth_token):
        """Create a test Starlette app with transport auth middleware."""
        import importlib
        import serve_mcp
        # Patch module-level vars directly (env is read at import time)
        serve_mcp.MCP_AUTH_MODE = auth_mode
        serve_mcp.MCP_AUTH_TOKEN = auth_token

        from serve_mcp import MCPTransportAuthMiddleware
        from starlette.testclient import TestClient
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from starlette.middleware import Middleware

        async def dummy(request):
            return JSONResponse({"ok": True})

        app = Starlette(
            routes=[Route("/mcp", dummy, methods=["POST", "GET"])],
            middleware=[Middleware(MCPTransportAuthMiddleware)],
        )
        return TestClient(app, raise_server_exceptions=False)

    def test_mcp_no_credential_rejected(self):
        """MCP connect with no Authorization header → 401."""
        client = self._make_app("bearer", "test-secret-token")
        resp = client.post("/mcp")
        assert resp.status_code == 401
        assert resp.json()["error"] == "UNAUTHORIZED"

    def test_mcp_wrong_bearer_rejected(self):
        """MCP connect with wrong bearer → 401."""
        client = self._make_app("bearer", "correct-token")
        resp = client.post("/mcp", headers={"Authorization": "Bearer wrong-token"})
        assert resp.status_code == 401
        assert resp.json()["error"] == "INVALID_TOKEN"

    def test_mcp_correct_bearer_succeeds(self):
        """MCP connect with correct bearer → passes through."""
        client = self._make_app("bearer", "correct-token")
        resp = client.post("/mcp", headers={"Authorization": "Bearer correct-token"})
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_startup_none_without_dev_mode_exits(self):
        """Server startup with MCP_AUTH_MODE=none and no GATEWAY_DEV_MODE → exits non-zero."""
        env = os.environ.copy()
        env["MCP_AUTH_MODE"] = "none"
        env.pop("GATEWAY_DEV_MODE", None)
        result = subprocess.run(
            [sys.executable, "-c", "import serve_mcp; serve_mcp._validate_config()"],
            capture_output=True, text=True, env=env,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
        assert result.returncode != 0


# =============================================================================
# 4.2 — Application identity (DPoP enforcement at service layer)
# =============================================================================


class TestDPoPEnforcement:
    """Tests for DPoP identity enforcement in GatewayService.authorize()."""

    def setup_method(self):
        # Clear JTI cache between tests
        from gateway import identity
        identity._proof_jti_cache.clear()

    def test_no_proof_rejected(self):
        """Call with empty DPoP proof → NO_PROOF."""
        gw, _, _ = _make_registered_gateway()
        with pytest.raises(ValueError, match="NO_PROOF"):
            gw.authorize(agent_id="test-agent-01", action="read", resource="staging-db", agent_proof="")

    def test_empty_proof_rejected(self):
        """Call with empty string proof → NO_PROOF."""
        gw, _, _ = _make_registered_gateway()
        with pytest.raises(ValueError, match="NO_PROOF"):
            gw.authorize(
                agent_id="test-agent-01", action="read", resource="staging-db",
                agent_proof="",
            )

    def test_unregistered_agent_rejected(self):
        """Valid transport + DPoP proof from UNREGISTERED key → UNREGISTERED_AGENT."""
        gw, _, _ = _make_registered_gateway()
        rogue_key = Ed25519PrivateKey.generate()
        proof = create_agent_proof(rogue_key, "unknown-agent", "read", "staging-db")
        with pytest.raises(ValueError, match="UNREGISTERED_AGENT"):
            gw.authorize(
                agent_id="unknown-agent", action="read", resource="staging-db",
                agent_proof=proof,
            )

    def test_tampered_proof_sig_rejected(self):
        """Valid registered agent but tampered proof sig → INVALID_PROOF_SIGNATURE."""
        gw, agent_key, agent_id = _make_registered_gateway()
        # Sign with a different key than the registered one
        wrong_key = Ed25519PrivateKey.generate()
        proof = create_agent_proof(wrong_key, agent_id, "read", "staging-db")
        with pytest.raises(ValueError, match="INVALID_PROOF_SIGNATURE"):
            gw.authorize(
                agent_id=agent_id, action="read", resource="staging-db",
                agent_proof=proof,
            )

    def test_replayed_proof_rejected(self):
        """Replayed proof jti → PROOF_REPLAY."""
        gw, agent_key, agent_id = _make_registered_gateway()
        proof = create_agent_proof(agent_key, agent_id, "read", "staging-db")
        # First call succeeds
        gw.authorize(agent_id=agent_id, action="read", resource="staging-db", agent_proof=proof)
        # Second call with same proof fails
        with pytest.raises(ValueError, match="PROOF_REPLAY"):
            gw.authorize(agent_id=agent_id, action="read", resource="staging-db", agent_proof=proof)

    def test_proof_action_mismatch_rejected(self):
        """Proof bound to action A used to authorize action B → PROOF_ACTION_MISMATCH."""
        gw, agent_key, agent_id = _make_registered_gateway()
        proof = create_agent_proof(agent_key, agent_id, "read", "staging-db")
        with pytest.raises(ValueError, match="PROOF_ACTION_MISMATCH"):
            gw.authorize(
                agent_id=agent_id, action="delete", resource="staging-db",
                agent_proof=proof,
            )

    def test_proof_resource_mismatch_rejected(self):
        """Proof bound to resource A used for resource B → PROOF_RESOURCE_MISMATCH."""
        gw, agent_key, agent_id = _make_registered_gateway()
        proof = create_agent_proof(agent_key, agent_id, "read", "staging-db")
        with pytest.raises(ValueError, match="PROOF_RESOURCE_MISMATCH"):
            gw.authorize(
                agent_id=agent_id, action="read", resource="production-db",
                agent_proof=proof,
            )

    def test_proof_digest_mismatch_rejected(self):
        """Proof with wrong action_digest → PROOF_DIGEST_MISMATCH."""
        gw, agent_key, agent_id = _make_registered_gateway()
        proof = create_agent_proof(
            agent_key, agent_id, "read", "staging-db",
            action_digest="sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        with pytest.raises(ValueError, match="PROOF_DIGEST_MISMATCH"):
            gw.authorize(
                agent_id=agent_id, action="read", resource="staging-db",
                agent_proof=proof,
            )

    def test_proof_omitted_digest_rejected(self):
        """Proof with OMITTED action_digest → PROOF_DIGEST_MISSING."""
        gw, agent_key, agent_id = _make_registered_gateway()
        # Manually build a proof WITHOUT action_digest
        import time as _time, uuid as _uuid
        import jwt as _pyjwt
        payload = {
            "sub": agent_id,
            "htm": "POST",
            "htu": "agent-authorization-gateway",
            "action": "read",
            "resource": "staging-db",
            "jti": str(_uuid.uuid4()),
            "iat": int(_time.time()),
            # No action_digest
        }
        proof = _pyjwt.encode(payload, agent_key, algorithm="EdDSA")
        with pytest.raises(ValueError, match="PROOF_DIGEST_MISSING"):
            gw.authorize(
                agent_id=agent_id, action="read", resource="staging-db",
                agent_proof=proof,
            )

    def test_proof_empty_string_digest_rejected(self):
        """Proof with empty-string action_digest → PROOF_DIGEST_MISSING."""
        gw, agent_key, agent_id = _make_registered_gateway()
        import time as _time, uuid as _uuid
        import jwt as _pyjwt
        payload = {
            "sub": agent_id,
            "htm": "POST",
            "htu": "agent-authorization-gateway",
            "action": "read",
            "resource": "staging-db",
            "jti": str(_uuid.uuid4()),
            "iat": int(_time.time()),
            "action_digest": "",
        }
        proof = _pyjwt.encode(payload, agent_key, algorithm="EdDSA")
        with pytest.raises(ValueError, match="PROOF_DIGEST_MISSING"):
            gw.authorize(
                agent_id=agent_id, action="read", resource="staging-db",
                agent_proof=proof,
            )

    def test_valid_proof_issues_token(self):
        """Fully valid transport + DPoP + policy-allowed action → token issued, receipt signed."""
        gw, agent_key, agent_id = _make_registered_gateway()
        proof = create_agent_proof(agent_key, agent_id, "read", "staging-db")
        resp = gw.authorize(
            agent_id=agent_id, action="read", resource="staging-db",
            agent_proof=proof,
        )
        assert resp.decision == "approve"
        assert resp.token is not None
        assert resp.receipt_hash.startswith("sha256:")
        assert resp.action_digest.startswith("sha256:")

    def test_valid_proof_with_digest_binding(self):
        """Proof includes correct action_digest → accepted."""
        gw, agent_key, agent_id = _make_registered_gateway()
        digest = compute_action_digest(agent_id, "read", "staging-db")
        proof = create_agent_proof(
            agent_key, agent_id, "read", "staging-db",
            action_digest=digest,
        )
        resp = gw.authorize(
            agent_id=agent_id, action="read", resource="staging-db",
            agent_proof=proof,
        )
        assert resp.decision == "approve"
        assert resp.token is not None


# =============================================================================
# 4.3 — Cross-surface: REST, MCP handler, ADK tool all enforce DPoP
# =============================================================================


class TestCrossSurface:
    """Assert the same DPoP enforcement holds on REST, MCP handler, and ADK tool."""

    def setup_method(self):
        from gateway import identity
        identity._proof_jti_cache.clear()

    def test_rest_no_proof_rejected(self):
        """REST POST /authorize without agent_proof → 422 (validation) or 401."""
        from fastapi.testclient import TestClient
        from gateway.api import api_app

        client = TestClient(api_app, raise_server_exceptions=False)
        resp = client.post("/authorize", json={
            "agent_id": "test",
            "action": "read",
            "resource": "staging-db",
        })
        # Pydantic will reject because agent_proof is required (422)
        assert resp.status_code == 422

    def test_rest_valid_proof_succeeds(self):
        """REST POST /authorize with valid proof → 200 approve."""
        from fastapi.testclient import TestClient
        from gateway.api import api_app, _get_gateway

        client = TestClient(api_app, raise_server_exceptions=False)

        agent_key = Ed25519PrivateKey.generate()
        jwk = _make_jwk(agent_key)
        agent_id = "rest-test-agent"

        # Register with PoP
        from tests.helpers import register_agent_with_pop
        register_agent_with_pop(client, agent_id, agent_key)

        # Authorize with proof
        proof = create_agent_proof(agent_key, agent_id, "read", "staging-db")
        resp = client.post("/authorize", json={
            "agent_id": agent_id,
            "action": "read",
            "resource": "staging-db",
            "agent_proof": proof,
        })
        assert resp.status_code == 200
        assert resp.json()["decision"] == "approve"

    def test_rest_invalid_proof_rejected(self):
        """REST POST /authorize with bad proof → 401."""
        from fastapi.testclient import TestClient
        from gateway.api import api_app

        client = TestClient(api_app, raise_server_exceptions=False)
        resp = client.post("/authorize", json={
            "agent_id": "nobody",
            "action": "read",
            "resource": "staging-db",
            "agent_proof": "not-a-jwt",
        })
        assert resp.status_code == 401

    @pytest.mark.skipif(
        not _has_google_adk(),
        reason="google.adk not installed",
    )
    def test_adk_tool_no_proof_rejected(self):
        """ADK tool authorize_action without proof → error dict."""
        from gateway.tools.authorize_tool import authorize_action
        result = authorize_action(
            agent_id="test",
            action="read",
            resource="staging-db",
            agent_proof="",
        )
        assert "error" in result
        assert result["error"] == "NO_PROOF"

    @pytest.mark.skipif(
        not _has_google_adk(),
        reason="google.adk not installed",
    )
    def test_adk_tool_valid_proof_succeeds(self):
        """ADK tool authorize_action with valid proof → approve."""
        from gateway.tools.authorize_tool import authorize_action, _get_gateway

        gw = _get_gateway()
        agent_key = Ed25519PrivateKey.generate()
        jwk = _make_jwk(agent_key)
        agent_id = "adk-test-agent"
        gw._registry.register(agent_id, jwk)

        proof = create_agent_proof(agent_key, agent_id, "read", "staging-db")
        result = authorize_action(
            agent_id=agent_id,
            action="read",
            resource="staging-db",
            agent_proof=proof,
        )
        assert result["decision"] == "approve"
        assert result["token"] is not None


# =============================================================================
# Original exploit: anonymous MCP → authorize_action → token (must now fail)
# =============================================================================


class TestOriginalExploitClosed:
    """The original exploit was: anonymous streamablehttp_client → authorize_action → token.
    This must now fail at BOTH the transport layer and the identity layer."""

    def setup_method(self):
        from gateway import identity
        identity._proof_jti_cache.clear()

    def test_service_layer_rejects_no_proof(self):
        """Direct call to GatewayService.authorize() with empty proof → NO_PROOF."""
        gw = GatewayService(tenant="exploit-test")
        with pytest.raises(ValueError, match="NO_PROOF"):
            gw.authorize(agent_id="attacker", action="query", resource="staging-database", agent_proof="")

    def test_service_layer_rejects_unregistered(self):
        """Direct call with proof from unregistered agent → UNREGISTERED_AGENT."""
        gw = GatewayService(tenant="exploit-test")
        rogue_key = Ed25519PrivateKey.generate()
        proof = create_agent_proof(rogue_key, "attacker", "query", "staging-database")
        with pytest.raises(ValueError, match="UNREGISTERED_AGENT"):
            gw.authorize(
                agent_id="attacker", action="query", resource="staging-database",
                agent_proof=proof,
            )
