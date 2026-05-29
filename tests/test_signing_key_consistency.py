"""Tests for signing key consistency — regression guards against kid drift.

These tests verify that the loaded signing key, the published JWK from
get_public_jwk(), and newly-issued receipts all use the SAME kid. If any
of these tests fail, it means a code change decoupled the key loading from
the JWK publishing — the bug class that caused the KID_MISMATCH incident.

These tests run without Secret Manager access by using the
GATEWAY_LOCAL_SIGNING_KEY env var override.
"""

import base64
import json
import os
import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

# Generate a test key and set it in env BEFORE importing gateway modules
_test_key = Ed25519PrivateKey.generate()
_test_pem = _test_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
_test_kid = "test-consistency-key"
os.environ["GATEWAY_LOCAL_SIGNING_KEY"] = json.dumps({
    "kid": _test_kid,
    "private_pem": _test_pem,
})
os.environ["FIRESTORE_ENABLED"] = ""

# Clear any cached key from prior test modules
from gateway import signing_key as _sk_mod
_sk_mod._cached_kid = None
_sk_mod._cached_key = None

from gateway.signing_key import load_signing_key, get_public_jwk


class TestSigningKeyConsistency:
    def setup_method(self):
        # Reset cache between tests
        _sk_mod._cached_kid = None
        _sk_mod._cached_key = None

    def test_loaded_key_matches_published_jwk(self):
        """Regression guard: kid in /keys matches kid of loaded signing key."""
        kid, _ = load_signing_key()
        jwk = get_public_jwk()
        assert jwk["kid"] == kid, (
            f"kid drift detected: loaded kid={kid} but published "
            f"jwk kid={jwk['kid']}. These MUST match — see "
            f"SECURITY.md trust assumption #1."
        )

    def test_loaded_key_signs_and_published_jwk_verifies(self):
        """Regression guard: signatures from loaded key verify against /keys JWK."""
        _, priv = load_signing_key()
        jwk = get_public_jwk()

        payload = secrets.token_bytes(32)
        sig = priv.sign(payload)

        x = jwk["x"]
        padding = 4 - len(x) % 4
        if padding != 4:
            x += "=" * padding
        pub = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(x))
        pub.verify(sig, payload)  # raises InvalidSignature on failure

    def test_newly_issued_receipt_kid_matches_published_jwk(self):
        """Regression guard: receipt sig.kid matches published jwk kid."""
        from gateway.identity import AgentRegistry, create_agent_proof
        from gateway import identity
        identity._proof_jti_cache.clear()

        kid, priv = load_signing_key()
        jwk = get_public_jwk()

        # Create a GatewayService with the loaded key
        from gateway.gateway_service import GatewayService
        registry = AgentRegistry()
        agent_key = Ed25519PrivateKey.generate()
        pub_bytes = agent_key.public_key().public_bytes_raw()
        agent_jwk = {
            "kty": "OKP", "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode(),
        }
        registry.register("test-agent", agent_jwk)

        gw = GatewayService(
            tenant="test",
            registry=registry,
            private_key=priv,
            kid=kid,
        )

        # Issue a receipt via the normal authorize path
        proof = create_agent_proof(agent_key, "test-agent", "read", "staging-db")
        resp = gw.authorize(
            agent_id="test-agent",
            action="read",
            resource="staging-db",
            agent_proof=proof,
        )

        receipt_kid = resp.receipt["sig"]["kid"]
        assert receipt_kid == jwk["kid"], (
            f"receipt signed with kid={receipt_kid} but /keys publishes "
            f"kid={jwk['kid']}"
        )
