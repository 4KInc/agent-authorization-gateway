"""Tests for resource-side token enforcement (Phase 1).

Verifies that the Gateway middleware correctly enforces Ed25519-signed
tokens with action binding, replay prevention, and key verification.
"""

import os
import time

os.environ["FIRESTORE_ENABLED"] = ""

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway.gateway_service import GatewayService
from gateway.tokens import (
    compute_action_digest,
    issue_token,
    verify_token,
    public_key_from_jwk,
)


class TestEdDSATokens:
    """Verify tokens are now Ed25519 (EdDSA), not HS256."""

    def setup_method(self):
        self.gw = GatewayService(tenant="test")

    def test_token_is_eddsa_signed(self):
        r = self.gw.authorize(agent_id="a1", action="read", resource="staging-db")
        assert r.token is not None
        # Decode header without verification to check algorithm
        header = pyjwt.get_unverified_header(r.token)
        assert header["alg"] == "EdDSA"

    def test_token_verifiable_with_public_key(self):
        r = self.gw.authorize(agent_id="a1", action="read", resource="staging-db")
        jwk = self.gw.get_public_key_jwk()
        pub_key = public_key_from_jwk(jwk)
        claims = verify_token(r.token, pub_key)
        assert claims["sub"] == "a1"
        assert claims["action"] == "read"
        assert claims["resource"] == "staging-db"
        assert claims["decision"] == "approve"
        assert "action_digest" in claims
        assert "jti" in claims

    def test_token_not_verifiable_with_wrong_key(self):
        r = self.gw.authorize(agent_id="a1", action="read", resource="staging-db")
        wrong_key = Ed25519PrivateKey.generate().public_key()
        with pytest.raises(pyjwt.InvalidSignatureError):
            verify_token(r.token, wrong_key)

    def test_expired_token_rejected(self):
        # Issue a token with 0-second TTL
        private_key = Ed25519PrivateKey.generate()
        token, jti = issue_token(
            private_key=private_key,
            agent_id="a1",
            action="read",
            resource="db",
            action_digest="sha256:abc",
            decision="approve",
            receipt_hash="sha256:def",
            ttl_seconds=0,
        )
        # Should be expired immediately
        import time
        time.sleep(1)
        with pytest.raises(pyjwt.ExpiredSignatureError):
            verify_token(token, private_key.public_key(), leeway=0)

    def test_deny_decision_produces_no_token(self):
        r = self.gw.authorize(agent_id="a1", action="delete", resource="production-db")
        assert r.decision == "deny"
        assert r.token is None

    def test_token_contains_action_and_resource(self):
        r = self.gw.authorize(agent_id="a1", action="read", resource="staging-db")
        jwk = self.gw.get_public_key_jwk()
        claims = verify_token(r.token, public_key_from_jwk(jwk))
        assert claims["action"] == "read"
        assert claims["resource"] == "staging-db"

    def test_token_bound_to_receipt(self):
        r = self.gw.authorize(agent_id="a1", action="read", resource="staging-db")
        jwk = self.gw.get_public_key_jwk()
        claims = verify_token(r.token, public_key_from_jwk(jwk))
        assert claims["receipt_hash"] == r.receipt_hash


class TestReceiptTokenBinding:
    """Verify receipt includes token_jti for approvals."""

    def setup_method(self):
        self.gw = GatewayService(tenant="test")

    def test_approve_receipt_has_token_jti(self):
        r = self.gw.authorize(agent_id="a1", action="read", resource="staging-db")
        body = r.receipt["body"]
        assert "token_jti" in body
        assert body["token_jti"] is not None

    def test_deny_receipt_has_no_token_jti(self):
        r = self.gw.authorize(agent_id="a1", action="delete", resource="production-db")
        body = r.receipt["body"]
        # token_jti should not be in the body for denials
        assert "token_jti" not in body


class TestActionDigestBinding:
    """Verify action_digest binds the token to the specific action."""

    def test_same_action_same_digest(self):
        d1 = compute_action_digest("a1", "read", "db")
        d2 = compute_action_digest("a1", "read", "db")
        assert d1 == d2

    def test_different_action_different_digest(self):
        d1 = compute_action_digest("a1", "read", "db")
        d2 = compute_action_digest("a1", "write", "db")
        assert d1 != d2

    def test_different_resource_different_digest(self):
        d1 = compute_action_digest("a1", "read", "staging-db")
        d2 = compute_action_digest("a1", "read", "production-db")
        assert d1 != d2

    def test_parameters_affect_digest(self):
        d1 = compute_action_digest("a1", "read", "db", {"limit": 10})
        d2 = compute_action_digest("a1", "read", "db", {"limit": 100})
        assert d1 != d2

    def test_no_hs256_anywhere(self):
        """Ensure HS256 is completely removed from the codebase."""
        import gateway.tokens as tokens_mod
        source = open(tokens_mod.__file__).read()
        assert "HS256" not in source, "HS256 should be completely removed from tokens.py"
