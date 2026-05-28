"""Tests for tamper detection (Phase 2).

Verifies that modifying any part of a receipt or the chain
is detected by verify_receipt and verify_chain.
"""

import copy
import os

os.environ["FIRESTORE_ENABLED"] = ""

from gateway.anchor import AnchorRecord, LocalAnchorSink
from gateway.gateway_service import GatewayService
from gateway.verify import verify_chain, verify_receipt


class TestTamperDetection:
    """Verify tampering is detected at the specific receipt and field."""

    def setup_method(self):
        self.gw = GatewayService(tenant="tamper-test")
        # Build a chain of 5 receipts
        for action in ["read", "query", "list", "search", "analyze"]:
            self.gw.authorize(agent_id="a1", action=action, resource="staging-db")
        self.chain = self.gw.get_receipt_chain()
        self.jwk = self.gw.get_public_key_jwk()
        assert len(self.chain) == 5

    def test_unmodified_chain_passes(self):
        result = verify_chain(self.chain, self.jwk)
        assert result.receipt_integrity == "PASS"
        assert result.chain_validity == "PASS"
        assert result.errors == []

    def test_tamper_decision_field_detected(self):
        """Modify receipt 2's decision field → hash mismatch at receipt 2."""
        bad = copy.deepcopy(self.chain)
        bad[2]["body"]["decision"] = "deny-TAMPERED"
        result = verify_chain(bad, self.jwk)
        assert result.receipt_integrity == "FAIL"
        assert any("RECEIPT_HASH_MISMATCH" in e.get("code", "") for e in result.errors)

    def test_tamper_action_field_detected(self):
        """Modify receipt 3's request_digest → hash mismatch at receipt 3."""
        bad = copy.deepcopy(self.chain)
        bad[3]["body"]["request_digest"] = "sha256:" + "ff" * 32
        result = verify_chain(bad, self.jwk)
        assert result.receipt_integrity == "FAIL"

    def test_tamper_prev_receipt_detected(self):
        """Modify receipt 2's prev_receipt → chain break at receipt 2."""
        bad = copy.deepcopy(self.chain)
        bad[2]["body"]["prev_receipt"] = "sha256:" + "aa" * 32
        result = verify_chain(bad, self.jwk)
        # Should fail at either hash mismatch or chain break
        assert result.receipt_integrity == "FAIL" or result.chain_validity == "FAIL"

    def test_replace_signature_with_different_content(self):
        """Use a valid sig from receipt 0 on receipt 1's body → sig check fails."""
        bad = copy.deepcopy(self.chain)
        bad[1]["sig"]["value"] = self.chain[0]["sig"]["value"]  # wrong sig
        result = verify_chain(bad, self.jwk)
        assert result.receipt_integrity == "FAIL"
        assert any("SIGNATURE" in e.get("code", "") or "HASH" in e.get("code", "") for e in result.errors)

    def test_delete_receipt_from_middle(self):
        """Remove receipt 2 → sequence gap detected."""
        bad = copy.deepcopy(self.chain)
        del bad[2]  # remove the 3rd receipt
        result = verify_chain(bad, self.jwk)
        assert result.chain_validity == "FAIL"
        assert any("SEQUENCE_GAP" in e.get("code", "") for e in result.errors)

    def test_insert_duplicate_receipt(self):
        """Duplicate receipt 1 → sequence gap or chain break."""
        bad = copy.deepcopy(self.chain)
        bad.insert(2, copy.deepcopy(bad[1]))  # duplicate receipt at position 2
        result = verify_chain(bad, self.jwk)
        assert result.chain_validity == "FAIL" or result.receipt_integrity == "FAIL"

    def test_reorder_receipts(self):
        """Swap receipts 1 and 2 → chain break."""
        bad = copy.deepcopy(self.chain)
        bad[1], bad[2] = bad[2], bad[1]
        result = verify_chain(bad, self.jwk)
        assert result.chain_validity == "FAIL" or result.receipt_integrity == "FAIL"

    def test_tamper_single_receipt_verify(self):
        """verify_receipt catches tampered body."""
        bad = copy.deepcopy(self.chain[0])
        bad["body"]["tenant"] = "HACKED"
        result = verify_receipt(bad, self.jwk)
        assert result.receipt_integrity == "FAIL"

    def test_forge_receipt_hash(self):
        """Change receipt_hash to match tampered body → sig still fails."""
        import hashlib
        from gateway.canonical import canonicalize
        bad = copy.deepcopy(self.chain[0])
        bad["body"]["decision"] = "approve-FORGED"
        # Recompute hash to match tampered body
        body_bytes = canonicalize(bad["body"])
        bad["receipt_hash"] = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
        # But the signature is still over the original body
        result = verify_receipt(bad, self.jwk)
        assert result.receipt_integrity == "FAIL"
        assert any("SIGNATURE" in e.get("code", "") for e in result.errors)


class TestLocalAnchorSink:
    """Test the local file anchor sink."""

    def test_anchor_creates_file(self, tmp_path):
        import asyncio
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        sink = LocalAnchorSink(log_dir=str(tmp_path))
        key = Ed25519PrivateKey.generate()
        record = AnchorRecord(
            merkle_root="sha256:" + "ab" * 32,
            receipt_count=5,
            tenant="test",
        )

        result = asyncio.run(sink.anchor(record, key))
        assert result["sink"] == "local"
        assert "anchor_hash" in result

        # Verify file was created
        anchors = asyncio.run(sink.get_anchors("test"))
        assert len(anchors) == 1
        assert anchors[0]["merkle_root"] == record.merkle_root
        assert anchors[0]["receipt_count"] == 5

    def test_anchor_chain_linkage(self, tmp_path):
        import asyncio
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        sink = LocalAnchorSink(log_dir=str(tmp_path))
        key = Ed25519PrivateKey.generate()

        # Anchor twice
        for i in range(2):
            record = AnchorRecord(
                merkle_root=f"sha256:{'ab' * 32}",
                receipt_count=i + 1,
                tenant="test",
            )
            asyncio.run(sink.anchor(record, key))

        anchors = asyncio.run(sink.get_anchors("test"))
        assert len(anchors) == 2
        # Second anchor should reference first anchor's hash
        assert anchors[1]["prev_anchor_hash"] == anchors[0]["anchor_hash"]

    def test_anchor_is_signed(self, tmp_path):
        import asyncio
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        sink = LocalAnchorSink(log_dir=str(tmp_path))
        key = Ed25519PrivateKey.generate()
        record = AnchorRecord(merkle_root="sha256:" + "cd" * 32, receipt_count=1, tenant="test")
        asyncio.run(sink.anchor(record, key))

        anchors = asyncio.run(sink.get_anchors("test"))
        assert "sig" in anchors[0]
        assert len(anchors[0]["sig"]) > 20  # Ed25519 sig is ~86 chars base64
