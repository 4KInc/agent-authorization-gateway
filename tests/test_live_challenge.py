"""Tests for the agent live-challenge verification at registration."""

import base64
import json
import os
import time
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

os.environ["FIRESTORE_ENABLED"] = ""

from gateway.api import _verify_agent_liveness


def _make_jwk(key):
    pub = key.public_key().public_bytes_raw()
    return {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(pub).rstrip(b"=").decode()}


@pytest.mark.asyncio
async def test_skipped_when_url_not_provided():
    result = await _verify_agent_liveness(None, {}, "test", "test-tenant")
    assert result["status"] == "skipped"
    assert result["challenge_id"] is None


@pytest.mark.asyncio
async def test_verified_when_callback_signs_correctly():
    key = Ed25519PrivateKey.generate()
    jwk = _make_jwk(key)

    class MockResp:
        status_code = 200
        def json(self):
            return self._data
        def __init__(self, data):
            self._data = data

    original_post = None

    async def mock_post(url, json=None, headers=None):
        # Sign the challenge the same way the agent would
        canonical = json_module.dumps(json, separators=(",", ":"), sort_keys=True).encode()
        sig = base64.urlsafe_b64encode(key.sign(canonical)).rstrip(b"=").decode()
        return MockResp({"signature": sig})

    import json as json_module

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await _verify_agent_liveness(
            "https://agent.example.com/live-challenge",
            jwk, "test-agent", "test-tenant",
        )

    assert result["status"] == "verified"
    assert result["challenge_id"] is not None


@pytest.mark.asyncio
async def test_fails_when_callback_signs_with_wrong_key():
    key_registered = Ed25519PrivateKey.generate()
    key_signing = Ed25519PrivateKey.generate()
    jwk = _make_jwk(key_registered)

    class MockResp:
        status_code = 200
        def json(self):
            return self._data
        def __init__(self, data):
            self._data = data

    import json as json_module

    async def mock_post(url, json=None, headers=None):
        canonical = json_module.dumps(json, separators=(",", ":"), sort_keys=True).encode()
        sig = base64.urlsafe_b64encode(key_signing.sign(canonical)).rstrip(b"=").decode()
        return MockResp({"signature": sig})

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await _verify_agent_liveness(
            "https://agent.example.com/live-challenge",
            jwk, "test-agent", "test-tenant",
        )

    assert result["status"] == "failed"
    assert "signature" in result["reason"].lower()


@pytest.mark.asyncio
async def test_fails_when_callback_returns_non_200():
    key = Ed25519PrivateKey.generate()
    jwk = _make_jwk(key)

    class MockResp:
        status_code = 500

    async def mock_post(url, json=None, headers=None):
        return MockResp()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await _verify_agent_liveness(
            "https://agent.example.com/live-challenge",
            jwk, "test-agent", "test-tenant",
        )

    assert result["status"] == "failed"
    assert "500" in result["reason"]


@pytest.mark.asyncio
async def test_fails_when_callback_missing_signature():
    key = Ed25519PrivateKey.generate()
    jwk = _make_jwk(key)

    class MockResp:
        status_code = 200
        def json(self):
            return {"no_signature": "here"}

    async def mock_post(url, json=None, headers=None):
        return MockResp()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await _verify_agent_liveness(
            "https://agent.example.com/live-challenge",
            jwk, "test-agent", "test-tenant",
        )

    assert result["status"] == "failed"
    assert "missing" in result["reason"].lower()


@pytest.mark.asyncio
async def test_fails_when_callback_times_out():
    import httpx

    key = Ed25519PrivateKey.generate()
    jwk = _make_jwk(key)

    async def mock_post(url, json=None, headers=None):
        raise httpx.TimeoutException("test timeout")

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await _verify_agent_liveness(
            "https://agent.example.com/live-challenge",
            jwk, "test-agent", "test-tenant",
        )

    assert result["status"] == "failed"
    assert "timeout" in result["reason"].lower()
