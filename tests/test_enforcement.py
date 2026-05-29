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
from tests.helpers import make_registered_gateway, authorized_call


class TestEdDSATokens:
    """Verify tokens are now Ed25519 (EdDSA), not HS256."""

    def setup_method(self):
        from gateway import identity
        identity._proof_jti_cache.clear()
        self.gw, self.agent_key, self.agent_id = make_registered_gateway()

    def test_token_is_eddsa_signed(self):
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "read", "staging-db")
        assert r.token is not None
        header = pyjwt.get_unverified_header(r.token)
        assert header["alg"] == "EdDSA"

    def test_token_verifiable_with_public_key(self):
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "read", "staging-db")
        jwk = self.gw.get_public_key_jwk()
        pub_key = public_key_from_jwk(jwk)
        claims = verify_token(r.token, pub_key)
        assert claims["sub"] == self.agent_id
        assert claims["action"] == "read"
        assert claims["resource"] == "staging-db"
        assert claims["decision"] == "approve"
        assert "action_digest" in claims
        assert "jti" in claims

    def test_token_not_verifiable_with_wrong_key(self):
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "read", "staging-db")
        wrong_key = Ed25519PrivateKey.generate().public_key()
        with pytest.raises(pyjwt.InvalidSignatureError):
            verify_token(r.token, wrong_key)

    def test_expired_token_rejected(self):
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
        import time
        time.sleep(1)
        with pytest.raises(pyjwt.ExpiredSignatureError):
            verify_token(token, private_key.public_key(), leeway=0)

    def test_deny_decision_produces_no_token(self):
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "delete", "production-db")
        assert r.decision == "deny"
        assert r.token is None

    def test_token_contains_action_and_resource(self):
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "read", "staging-db")
        jwk = self.gw.get_public_key_jwk()
        claims = verify_token(r.token, public_key_from_jwk(jwk))
        assert claims["action"] == "read"
        assert claims["resource"] == "staging-db"

    def test_token_bound_to_receipt(self):
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "read", "staging-db")
        jwk = self.gw.get_public_key_jwk()
        claims = verify_token(r.token, public_key_from_jwk(jwk))
        assert claims["receipt_hash"] == r.receipt_hash


class TestReceiptTokenBinding:
    """Verify receipt includes token_jti for approvals."""

    def setup_method(self):
        from gateway import identity
        identity._proof_jti_cache.clear()
        self.gw, self.agent_key, self.agent_id = make_registered_gateway()

    def test_approve_receipt_has_token_jti(self):
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "read", "staging-db")
        body = r.receipt["body"]
        assert "token_jti" in body
        assert body["token_jti"] is not None

    def test_deny_receipt_has_no_token_jti(self):
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "delete", "production-db")
        body = r.receipt["body"]
        assert "token_jti" not in body

    def test_approve_token_jti_matches_receipt_token_jti(self):
        """The returned token's jti MUST equal the receipt body's token_jti.

        This guards against the double-issuance bug where two tokens were
        generated with different jtis, and the receipt recorded jti₁ while
        the caller received jti₂.
        """
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "read", "staging-db")
        assert r.token is not None
        token_claims = pyjwt.decode(r.token, options={"verify_signature": False})
        receipt_jti = r.receipt["body"]["token_jti"]
        assert token_claims["jti"] == receipt_jti, (
            f"token jti {token_claims['jti']} != receipt token_jti {receipt_jti}"
        )

    def test_exactly_one_token_jti_per_approval(self):
        """Only one jti should exist per approved authorization — no double issuance."""
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "read", "staging-db")
        token_claims = pyjwt.decode(r.token, options={"verify_signature": False})
        # The receipt's token_jti and the token's jti must be the same single value
        assert r.receipt["body"]["token_jti"] == token_claims["jti"]
        # And the token was issued exactly once (receipt_hash in token is the real one, not "pending")
        assert token_claims["receipt_hash"] == r.receipt_hash
        assert token_claims["receipt_hash"] != "pending"

    def test_deny_produces_no_token_and_null_jti(self):
        """DENY: no token issued, receipt has no token_jti field."""
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "delete", "production-db")
        assert r.decision == "deny"
        assert r.token is None
        assert "token_jti" not in r.receipt["body"]


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
