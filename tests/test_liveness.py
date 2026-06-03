"""Tests for continuous attestation (Step 4: liveness re-verification).

Covers:
- LivenessRecord state machine (graduated failures)
- LivenessManager operations
- API endpoints for liveness queries and manual checks
- Lazy liveness denial on authorize
"""

import base64
import json
import os
import time
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

os.environ["FIRESTORE_ENABLED"] = ""

from gateway.liveness import LivenessManager, LivenessRecord, LivenessState


# ===========================================================================
# Unit tests: LivenessRecord state machine
# ===========================================================================

class TestLivenessRecord:
    def test_initial_state_is_unknown(self):
        r = LivenessRecord(agent_id="agent-1")
        assert r.state == LivenessState.UNKNOWN
        assert r.consecutive_failures == 0
        assert r.liveness_verified_at is None

    def test_success_transitions_to_live(self):
        r = LivenessRecord(agent_id="agent-1")
        r.record_success()
        assert r.state == LivenessState.LIVE
        assert r.consecutive_failures == 0
        assert r.total_successes == 1
        assert r.liveness_verified_at is not None

    def test_one_failure_transitions_to_warning(self):
        r = LivenessRecord(agent_id="agent-1")
        r.record_success()
        r.record_failure("timeout")
        assert r.state == LivenessState.WARNING
        assert r.consecutive_failures == 1

    def test_two_failures_transitions_to_stale(self):
        r = LivenessRecord(agent_id="agent-1")
        r.record_failure("timeout")
        r.record_failure("timeout")
        assert r.state == LivenessState.STALE
        assert r.consecutive_failures == 2

    def test_three_failures_transitions_to_suspended(self):
        r = LivenessRecord(agent_id="agent-1")
        r.record_failure("timeout")
        r.record_failure("timeout")
        r.record_failure("timeout")
        assert r.state == LivenessState.SUSPENDED
        assert r.consecutive_failures == 3

    def test_success_after_failures_resets_to_live(self):
        r = LivenessRecord(agent_id="agent-1")
        r.record_failure("timeout")
        r.record_failure("timeout")
        assert r.state == LivenessState.STALE
        r.record_success()
        assert r.state == LivenessState.LIVE
        assert r.consecutive_failures == 0

    def test_should_deny_when_stale(self):
        r = LivenessRecord(agent_id="agent-1")
        r.record_failure("timeout")
        r.record_failure("timeout")
        assert r.should_deny_authorization()

    def test_should_deny_when_suspended(self):
        r = LivenessRecord(agent_id="agent-1")
        for _ in range(3):
            r.record_failure("timeout")
        assert r.should_deny_authorization()

    def test_should_not_deny_when_live(self):
        r = LivenessRecord(agent_id="agent-1")
        r.record_success()
        assert not r.should_deny_authorization()

    def test_should_not_deny_when_warning(self):
        r = LivenessRecord(agent_id="agent-1")
        r.record_failure("timeout")
        assert r.state == LivenessState.WARNING
        assert not r.should_deny_authorization()

    def test_should_not_deny_when_unknown(self):
        """UNKNOWN agents (no liveness URL) should not be denied."""
        r = LivenessRecord(agent_id="agent-1")
        assert r.state == LivenessState.UNKNOWN
        assert not r.should_deny_authorization()

    def test_is_stale_when_never_verified(self):
        r = LivenessRecord(agent_id="agent-1")
        assert r.is_stale(interval=3600)

    def test_is_stale_when_old(self):
        r = LivenessRecord(agent_id="agent-1")
        r.liveness_verified_at = time.time() - 7200
        assert r.is_stale(interval=3600)

    def test_not_stale_when_recent(self):
        r = LivenessRecord(agent_id="agent-1")
        r.liveness_verified_at = time.time() - 10
        assert not r.is_stale(interval=3600)

    def test_history_is_rolling(self):
        r = LivenessRecord(agent_id="agent-1")
        for i in range(25):
            r.record_success()
        assert len(r.history) == 20  # MAX_HISTORY_ENTRIES

    def test_to_dict_includes_all_fields(self):
        r = LivenessRecord(agent_id="agent-1", live_challenge_url="https://example.com/lc")
        r.record_success()
        d = r.to_dict()
        assert d["agent_id"] == "agent-1"
        assert d["state"] == "LIVE"
        assert d["total_checks"] == 1
        assert d["live_challenge_url"] == "https://example.com/lc"
        assert d["liveness_verified_at"] is not None


# ===========================================================================
# Unit tests: LivenessManager
# ===========================================================================

class TestLivenessManager:
    def test_get_or_create(self):
        mgr = LivenessManager()
        r = mgr.get_or_create("agent-1", "https://example.com/lc")
        assert r.agent_id == "agent-1"
        assert r.live_challenge_url == "https://example.com/lc"
        # Second call returns same record
        r2 = mgr.get_or_create("agent-1")
        assert r2 is r

    def test_get_or_create_updates_url(self):
        mgr = LivenessManager()
        mgr.get_or_create("agent-1", "https://old.com/lc")
        r = mgr.get_or_create("agent-1", "https://new.com/lc")
        assert r.live_challenge_url == "https://new.com/lc"

    def test_remove(self):
        mgr = LivenessManager()
        mgr.get_or_create("agent-1")
        mgr.remove("agent-1")
        assert mgr.get("agent-1") is None

    def test_agents_needing_check(self):
        mgr = LivenessManager(attestation_interval=60)
        # Agent with URL and stale liveness
        r1 = mgr.get_or_create("agent-1", "https://example.com/lc")
        # Agent without URL
        r2 = mgr.get_or_create("agent-2")
        # Agent with recent liveness
        r3 = mgr.get_or_create("agent-3", "https://example.com/lc")
        r3.liveness_verified_at = time.time()

        needing = mgr.agents_needing_check()
        ids = [r.agent_id for r in needing]
        assert "agent-1" in ids
        assert "agent-2" not in ids  # no URL
        assert "agent-3" not in ids  # recently checked


# ===========================================================================
# Integration tests: API endpoints
# ===========================================================================

from fastapi.testclient import TestClient
from gateway.api import api_app, _get_gateway, _get_liveness
from gateway.identity import create_agent_proof

client = TestClient(api_app)

_agent_key = Ed25519PrivateKey.generate()
_agent_id = "liveness-test-agent"


def _make_jwk(key):
    pub_bytes = key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


def _register_agent():
    gw = _get_gateway()
    if gw._registry.get(_agent_id) is None:
        gw._registry.register(_agent_id, _make_jwk(_agent_key))


def test_liveness_list_initially_empty_or_has_entries():
    resp = client.get("/agents/liveness")
    assert resp.status_code == 200
    data = resp.json()
    assert "agents" in data
    assert "summary" in data
    assert "attestation_interval" in data


def test_liveness_404_for_unknown_agent():
    resp = client.get("/agents/nonexistent-agent-xyz/liveness")
    assert resp.status_code == 404


def test_liveness_check_404_for_unregistered_agent():
    resp = client.post("/agents/nonexistent-agent-xyz/liveness/check")
    assert resp.status_code == 404


def test_liveness_check_skipped_without_url():
    """Agent registered without live_challenge_url gets 'skipped' on check."""
    _register_agent()
    liveness_mgr = _get_liveness()
    liveness_mgr.get_or_create(_agent_id)  # No URL

    resp = client.post(f"/agents/{_agent_id}/liveness/check")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "skipped"


def test_authorize_denied_when_agent_stale():
    """Agents with STALE liveness should be denied at authorize."""
    from gateway import identity
    identity._proof_jti_cache.clear()
    _register_agent()

    # Force agent to STALE state
    liveness_mgr = _get_liveness()
    record = liveness_mgr.get_or_create(_agent_id, "https://example.com/lc")
    record.record_failure("timeout")
    record.record_failure("timeout")
    assert record.state == LivenessState.STALE

    proof = create_agent_proof(_agent_key, _agent_id, "read", "staging-db")
    resp = client.post("/authorize", json={
        "agent_id": _agent_id,
        "action": "read",
        "resource": "staging-db",
        "agent_proof": proof,
    })
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail["error"] == "LIVENESS_STALE"
    assert detail["liveness_state"] == "STALE"

    # Clean up: restore to LIVE
    record.record_success()


def test_authorize_denied_when_agent_suspended():
    """Agents with SUSPENDED liveness should be denied at authorize."""
    from gateway import identity
    identity._proof_jti_cache.clear()
    _register_agent()

    liveness_mgr = _get_liveness()
    record = liveness_mgr.get_or_create(_agent_id, "https://example.com/lc")
    for _ in range(3):
        record.record_failure("timeout")
    assert record.state == LivenessState.SUSPENDED

    proof = create_agent_proof(_agent_key, _agent_id, "read", "staging-db")
    resp = client.post("/authorize", json={
        "agent_id": _agent_id,
        "action": "read",
        "resource": "staging-db",
        "agent_proof": proof,
    })
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "LIVENESS_SUSPENDED"

    # Clean up
    record.record_success()


def test_authorize_allowed_when_agent_warning():
    """Agents with WARNING liveness (1 failure) should still be authorized."""
    from gateway import identity
    identity._proof_jti_cache.clear()
    _register_agent()

    liveness_mgr = _get_liveness()
    record = liveness_mgr.get_or_create(_agent_id, "https://example.com/lc")
    record.record_success()  # Reset to clean state
    record.record_failure("timeout")
    assert record.state == LivenessState.WARNING

    proof = create_agent_proof(_agent_key, _agent_id, "read", "staging-db")
    resp = client.post("/authorize", json={
        "agent_id": _agent_id,
        "action": "read",
        "resource": "staging-db",
        "agent_proof": proof,
    })
    assert resp.status_code == 200
    assert resp.json()["decision"] == "approve"

    # Clean up
    record.record_success()


def test_authorize_allowed_when_agent_unknown():
    """Agents with UNKNOWN liveness (no URL) should still be authorized."""
    from gateway import identity
    identity._proof_jti_cache.clear()
    _register_agent()

    liveness_mgr = _get_liveness()
    # Remove any existing record and create fresh UNKNOWN one
    liveness_mgr.remove(_agent_id)
    record = liveness_mgr.get_or_create(_agent_id)
    assert record.state == LivenessState.UNKNOWN

    proof = create_agent_proof(_agent_key, _agent_id, "read", "staging-db")
    resp = client.post("/authorize", json={
        "agent_id": _agent_id,
        "action": "read",
        "resource": "staging-db",
        "agent_proof": proof,
    })
    assert resp.status_code == 200

    # Clean up
    liveness_mgr.remove(_agent_id)


def test_authorize_allowed_when_no_liveness_record():
    """Agents without any liveness record should not be blocked."""
    from gateway import identity
    identity._proof_jti_cache.clear()
    _register_agent()

    liveness_mgr = _get_liveness()
    liveness_mgr.remove(_agent_id)
    assert liveness_mgr.get(_agent_id) is None

    proof = create_agent_proof(_agent_key, _agent_id, "read", "staging-db")
    resp = client.post("/authorize", json={
        "agent_id": _agent_id,
        "action": "read",
        "resource": "staging-db",
        "agent_proof": proof,
    })
    assert resp.status_code == 200


def test_liveness_sweep_endpoint():
    """POST /agents/liveness/sweep should return a summary."""
    resp = client.post("/agents/liveness/sweep")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert "checked" in data
    assert "passed" in data
    assert "failed" in data


# ===========================================================================
# Unit test: LivenessManager.check_agent with mocked HTTP
# ===========================================================================

@pytest.mark.asyncio
async def test_check_agent_success():
    """Successful liveness challenge should move agent to LIVE."""
    key = Ed25519PrivateKey.generate()
    jwk = _make_jwk(key)

    mgr = LivenessManager()
    mgr.get_or_create("test-agent", "https://agent.example.com/lc")

    import json as json_module

    async def mock_post(url, json=None, headers=None):
        canonical = json_module.dumps(json, separators=(",", ":"), sort_keys=True).encode()
        sig = base64.urlsafe_b64encode(key.sign(canonical)).rstrip(b"=").decode()

        class Resp:
            status_code = 200
            def json(self_):
                return {"signature": sig}
        return Resp()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        record = await mgr.check_agent("test-agent", jwk, "test-tenant")

    assert record.state == LivenessState.LIVE
    assert record.total_successes == 1


@pytest.mark.asyncio
async def test_check_agent_failure_wrong_key():
    """Challenge signed with wrong key should increment failure count."""
    registered_key = Ed25519PrivateKey.generate()
    signing_key = Ed25519PrivateKey.generate()
    jwk = _make_jwk(registered_key)

    mgr = LivenessManager()
    mgr.get_or_create("test-agent", "https://agent.example.com/lc")

    import json as json_module

    async def mock_post(url, json=None, headers=None):
        canonical = json_module.dumps(json, separators=(",", ":"), sort_keys=True).encode()
        sig = base64.urlsafe_b64encode(signing_key.sign(canonical)).rstrip(b"=").decode()

        class Resp:
            status_code = 200
            def json(self_):
                return {"signature": sig}
        return Resp()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        record = await mgr.check_agent("test-agent", jwk, "test-tenant")

    assert record.state == LivenessState.WARNING
    assert record.consecutive_failures == 1


@pytest.mark.asyncio
async def test_check_agent_timeout():
    """Timeout should be recorded as a failure."""
    import httpx as httpx_module

    key = Ed25519PrivateKey.generate()
    jwk = _make_jwk(key)

    mgr = LivenessManager()
    mgr.get_or_create("test-agent", "https://agent.example.com/lc")

    async def mock_post(url, json=None, headers=None):
        raise httpx_module.TimeoutException("test timeout")

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        record = await mgr.check_agent("test-agent", jwk, "test-tenant")

    assert record.state == LivenessState.WARNING
    assert "timeout" in record.last_failure_reason.lower()


@pytest.mark.asyncio
async def test_sweep_only_checks_stale_agents():
    """Sweep should only re-challenge agents with stale liveness."""
    from gateway.identity import AgentRegistry

    key1 = Ed25519PrivateKey.generate()
    key2 = Ed25519PrivateKey.generate()
    jwk1 = _make_jwk(key1)
    jwk2 = _make_jwk(key2)

    registry = AgentRegistry()
    registry.register("fresh-agent", jwk1, live_challenge_url="https://a.com/lc")
    registry.register("stale-agent", jwk2, live_challenge_url="https://b.com/lc")

    mgr = LivenessManager(attestation_interval=60)
    # Fresh agent — recently verified
    fresh = mgr.get_or_create("fresh-agent", "https://a.com/lc")
    fresh.liveness_verified_at = time.time()
    fresh.state = LivenessState.LIVE
    # Stale agent — never verified
    mgr.get_or_create("stale-agent", "https://b.com/lc")

    import json as json_module

    call_urls = []

    async def mock_post(url, json=None, headers=None):
        call_urls.append(url)
        # Sign with key2 (stale agent's key)
        canonical = json_module.dumps(json, separators=(",", ":"), sort_keys=True).encode()
        sig = base64.urlsafe_b64encode(key2.sign(canonical)).rstrip(b"=").decode()

        class Resp:
            status_code = 200
            def json(self_):
                return {"signature": sig}
        return Resp()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        summary = await mgr.sweep(registry, "test-tenant")

    assert summary["checked"] == 1  # Only stale agent
    assert "https://b.com/lc" in call_urls[0]
