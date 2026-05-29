"""Tests for bounded chain verification on /verify-receipt.

Verifies that single-receipt verification now checks the prev_receipt
link to the actual predecessor, detecting tampering without a full
chain walk.
"""

import copy
import os

os.environ["FIRESTORE_ENABLED"] = ""

from gateway.verify import verify_receipt, GENESIS_PREV_RECEIPT
from tests.helpers import make_registered_gateway, authorized_call


class TestBoundedChainVerification:
    def setup_method(self):
        from gateway import identity
        identity._proof_jti_cache.clear()
        self.gw, self.key, self.aid = make_registered_gateway()

    def test_genesis_receipt_returns_pass(self):
        """Genesis receipt (seq=1, prev=null hash) returns chain_validity=PASS."""
        resp = authorized_call(self.gw, self.key, self.aid, "read", "staging-db")
        chain = self.gw.get_receipt_chain()
        assert len(chain) == 1
        assert chain[0]["body"]["prev_receipt"] == GENESIS_PREV_RECEIPT

        result = verify_receipt(resp.receipt, self.gw.get_public_key_jwk(), chain=chain)
        assert result.receipt_integrity == "PASS"
        assert result.chain_validity == "PASS"
        assert result.errors == []

    def test_valid_link_returns_pass(self):
        """Second receipt with valid prev_receipt link returns chain_validity=PASS."""
        authorized_call(self.gw, self.key, self.aid, "read", "staging-db")
        resp2 = authorized_call(self.gw, self.key, self.aid, "query", "dev-db")
        chain = self.gw.get_receipt_chain()
        assert len(chain) == 2

        result = verify_receipt(resp2.receipt, self.gw.get_public_key_jwk(), chain=chain)
        assert result.receipt_integrity == "PASS"
        assert result.chain_validity == "PASS"
        assert result.errors == []

    def test_broken_link_returns_fail(self):
        """Tampered predecessor hash causes chain_validity=FAIL with PREV_LINK_BROKEN."""
        authorized_call(self.gw, self.key, self.aid, "read", "staging-db")
        resp2 = authorized_call(self.gw, self.key, self.aid, "query", "dev-db")
        chain = self.gw.get_receipt_chain()

        # Tamper the predecessor's receipt_hash so the link breaks
        tampered_chain = copy.deepcopy(chain)
        tampered_chain[0]["receipt_hash"] = "sha256:" + "ff" * 32

        result = verify_receipt(resp2.receipt, self.gw.get_public_key_jwk(), chain=tampered_chain)
        assert result.chain_validity == "FAIL"
        assert any(e["code"] == "PREV_LINK_BROKEN" for e in result.errors)

    def test_missing_predecessor_returns_inconclusive(self):
        """Missing predecessor returns chain_validity=INCONCLUSIVE with PREV_NOT_FOUND."""
        authorized_call(self.gw, self.key, self.aid, "read", "staging-db")
        resp2 = authorized_call(self.gw, self.key, self.aid, "query", "dev-db")

        # Chain with only the second receipt (predecessor missing)
        chain_missing_first = [self.gw.get_receipt_chain()[1]]

        result = verify_receipt(resp2.receipt, self.gw.get_public_key_jwk(), chain=chain_missing_first)
        assert result.receipt_integrity == "PASS"
        assert result.chain_validity == "INCONCLUSIVE"
        assert any(e["code"] == "PREV_NOT_FOUND" for e in result.errors)
