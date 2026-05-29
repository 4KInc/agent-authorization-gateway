"""Tests for Base L2 on-chain anchoring (Phase 2 anchoring upgrade).

Unit tests use mocks — no network access required.
"""

import os
import json
from unittest.mock import MagicMock, patch

os.environ["FIRESTORE_ENABLED"] = ""

import pytest

from gateway.base_anchor import (
    AnchorResult,
    BASE_MAINNET_CHAIN_ID,
    BURN_ADDRESS,
)


class TestAnchorRootCalldata:
    """Verify the transaction calldata matches the input root."""

    def test_calldata_matches_input_root(self):
        """Mock web3 and verify tx data == input root bytes."""
        root_hex = "ab" * 32  # 64 hex chars = 32 bytes
        root_bytes = bytes.fromhex(root_hex)

        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_w3.eth.chain_id = BASE_MAINNET_CHAIN_ID
        mock_w3.eth.get_transaction_count.return_value = 0
        mock_w3.eth.get_block.return_value = {"baseFeePerGas": 1000000}
        mock_w3.to_wei.return_value = 10000
        mock_w3.eth.send_raw_transaction.return_value = bytes.fromhex("ff" * 32)
        mock_w3.eth.wait_for_transaction_receipt.return_value = MagicMock(
            status=1, blockNumber=12345, gasUsed=21512
        )
        mock_w3.eth.get_block.return_value = MagicMock(timestamp=1735689600)

        mock_acct = MagicMock()
        mock_acct.sign_transaction.return_value = MagicMock(raw_transaction=b"\x00")

        # Capture the tx dict passed to sign_transaction
        built_tx = {}
        def capture_tx(tx):
            built_tx.update(tx)
            return MagicMock(raw_transaction=b"\x00")
        mock_acct.sign_transaction = capture_tx

        with patch("gateway.base_anchor.get_web3", return_value=mock_w3), \
             patch("gateway.base_anchor.load_anchor_wallet", return_value=(mock_acct, "0xAddr")):
            from gateway.base_anchor import anchor_root
            result = anchor_root("sha256:" + root_hex, chain_head_seq=42)

        # The tx data field must be exactly the root bytes
        assert built_tx["data"] == root_bytes
        assert built_tx["to"] == BURN_ADDRESS
        assert built_tx["value"] == 0
        assert built_tx["chainId"] == BASE_MAINNET_CHAIN_ID
        assert built_tx["gas"] == 30000

    def test_rejects_invalid_root_length(self):
        """A non-64-char hex input should ValueError before any RPC call."""
        from gateway.base_anchor import anchor_root
        with pytest.raises(ValueError, match="64 hex chars"):
            anchor_root("sha256:tooshort", chain_head_seq=1)

    def test_rejects_empty_root(self):
        from gateway.base_anchor import anchor_root
        with pytest.raises(ValueError):
            anchor_root("sha256:", chain_head_seq=1)


class TestAnchorResult:
    def test_to_dict_includes_basescan_url(self):
        result = AnchorResult(
            merkle_root="sha256:" + "ab" * 32,
            tx_hash="0x" + "cd" * 32,
            block_number=12345,
            block_timestamp=1735689600,
            chain_head_seq=42,
            confirmed=True,
        )
        d = result.to_dict()
        assert d["basescan_url"] == f"https://basescan.org/tx/0x{'cd' * 32}"
        assert d["chain_id"] == 8453
        assert d["confirmed"] is True


class TestVerifyAnchorOnChain:
    def test_verify_matches(self):
        root_hex = "ab" * 32
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_w3.eth.chain_id = BASE_MAINNET_CHAIN_ID
        mock_tx = MagicMock()
        mock_tx.input = bytes.fromhex(root_hex)
        mock_tx.blockNumber = 12345
        mock_w3.eth.get_transaction.return_value = mock_tx
        mock_w3.eth.get_block.return_value = MagicMock(timestamp=1735689600)

        with patch("gateway.base_anchor.get_web3", return_value=mock_w3):
            from gateway.base_anchor import verify_anchor_on_chain
            result = verify_anchor_on_chain("0xfake", expected_root="sha256:" + root_hex)

        assert result["tx_found"] is True
        assert result["calldata_matches_recorded_root"] is True

    def test_verify_mismatch(self):
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_w3.eth.chain_id = BASE_MAINNET_CHAIN_ID
        mock_tx = MagicMock()
        mock_tx.input = bytes.fromhex("ab" * 32)
        mock_tx.blockNumber = 12345
        mock_w3.eth.get_transaction.return_value = mock_tx
        mock_w3.eth.get_block.return_value = MagicMock(timestamp=1735689600)

        with patch("gateway.base_anchor.get_web3", return_value=mock_w3):
            from gateway.base_anchor import verify_anchor_on_chain
            result = verify_anchor_on_chain("0xfake", expected_root="sha256:" + "cd" * 32)

        assert result["tx_found"] is True
        assert result["calldata_matches_recorded_root"] is False


class TestAnchorEndpoint:
    def test_get_anchors_returns_list(self):
        from fastapi.testclient import TestClient
        from gateway.api import api_app
        client = TestClient(api_app)
        resp = client.get("/anchors")
        assert resp.status_code == 200
        data = resp.json()
        assert "on_chain_anchors" in data
        assert isinstance(data["on_chain_anchors"], list)
