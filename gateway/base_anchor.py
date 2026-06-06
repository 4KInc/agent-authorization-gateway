"""On-chain Merkle root anchoring to Base L2 mainnet.

Design properties:
- Async only. Never called from a synchronous trust path.
- Best-effort. Failures are logged but never propagate to callers.
- Batched. One anchor commits to N receipts or to an hourly
  chain-head snapshot, not per-receipt.
- Audit-quality. Each anchor produces a record with the tx hash,
  block number, block timestamp, and chain head seq at anchor time.
  Anyone can independently look up the transaction on BaseScan and
  confirm the Merkle root was committed at that block height.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("gateway.base_anchor")

BASE_MAINNET_CHAIN_ID = 8453
BURN_ADDRESS = "0x0000000000000000000000000000000000000000"
DEFAULT_BASE_RPC = "https://mainnet.base.org"
GCP_PROJECT = os.environ.get("GOOGLE_CLOUD_PROJECT", "quick-catcher-470218-b0")


@dataclass
class AnchorResult:
    merkle_root: str          # "sha256:<hex>"
    tx_hash: str              # "0x<64 hex chars>"
    block_number: int
    block_timestamp: int      # unix epoch
    chain_head_seq: int       # seq of the latest receipt at anchor time
    confirmed: bool

    def to_dict(self) -> dict:
        return {
            "merkle_root": self.merkle_root,
            "tx_hash": self.tx_hash,
            "block_number": self.block_number,
            "block_timestamp": self.block_timestamp,
            "chain_head_seq": self.chain_head_seq,
            "confirmed": self.confirmed,
            "chain_id": BASE_MAINNET_CHAIN_ID,
            "basescan_url": f"https://basescan.org/tx/{self.tx_hash}",
        }


def load_anchor_wallet():
    """Load wallet credentials from Secret Manager once at startup."""
    from google.cloud import secretmanager
    from eth_account import Account

    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{GCP_PROJECT}/secrets/gateway-anchor-wallet/versions/latest"
    response = client.access_secret_version(request={"name": name})
    payload = json.loads(response.payload.data.decode())
    return Account.from_key(payload["private_key"]), payload["address"]


def get_web3(rpc_url: Optional[str] = None):
    """Connect to Base mainnet via HTTP provider."""
    from web3 import Web3

    url = rpc_url or os.getenv("BASE_RPC_URL", DEFAULT_BASE_RPC)
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        raise RuntimeError(f"Could not connect to Base RPC at {url}")
    chain_id = w3.eth.chain_id
    if chain_id != BASE_MAINNET_CHAIN_ID:
        raise RuntimeError(
            f"Connected to chain_id={chain_id}, "
            f"expected Base mainnet ({BASE_MAINNET_CHAIN_ID})"
        )
    return w3


def anchor_root(
    merkle_root_sha256_hex: str,
    chain_head_seq: int,
) -> AnchorResult:
    """Submit a transaction to Base mainnet committing the Merkle root.

    The root (32 bytes) is included as the transaction's calldata.
    Recipient is the burn address. Value is 0.

    This function is synchronous (waits for confirmation) and should
    be called from a background task via run_in_executor().
    """
    # Parse root
    raw = merkle_root_sha256_hex
    if raw.startswith("sha256:"):
        raw = raw[7:]
    if len(raw) != 64:
        raise ValueError(f"Merkle root must be 64 hex chars, got {len(raw)}")
    root_bytes = bytes.fromhex(raw)

    w3 = get_web3()
    acct, address = load_anchor_wallet()

    nonce = w3.eth.get_transaction_count(address)
    try:
        base_fee = w3.eth.get_block("latest")["baseFeePerGas"]
    except Exception:
        # Public RPC may throttle get_block; use a safe default (0.1 gwei)
        base_fee = w3.to_wei(0.1, "gwei")
    max_priority_fee = w3.to_wei(0.01, "gwei")
    max_fee = base_fee * 2 + max_priority_fee

    tx = {
        "chainId": BASE_MAINNET_CHAIN_ID,
        "to": BURN_ADDRESS,
        "value": 0,
        "nonce": nonce,
        "gas": 30000,
        "maxFeePerGas": max_fee,
        "maxPriorityFeePerGas": max_priority_fee,
        "data": root_bytes,
        "type": 2,
    }
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    logger.info(
        "Anchor tx submitted: root=%s tx=%s chain_head_seq=%d",
        raw[:16], tx_hash.hex(), chain_head_seq,
    )

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    if receipt.status != 1:
        raise RuntimeError(f"Anchor tx {tx_hash.hex()} reverted on Base")

    try:
        block = w3.eth.get_block(receipt.blockNumber)
        block_ts = block.timestamp
    except Exception:
        # Public RPC may fail on recent block lookup; use current time
        import time
        block_ts = int(time.time())

    result = AnchorResult(
        merkle_root="sha256:" + raw,
        tx_hash="0x" + tx_hash.hex() if not tx_hash.hex().startswith("0x") else tx_hash.hex(),
        block_number=receipt.blockNumber,
        block_timestamp=block_ts,
        chain_head_seq=chain_head_seq,
        confirmed=True,
    )
    logger.info(
        "Anchor confirmed: tx=%s block=%d ts=%d gas=%d",
        result.tx_hash, result.block_number, result.block_timestamp, receipt.gasUsed,
    )
    return result


def verify_anchor_on_chain(tx_hash: str, expected_root: str | None = None) -> dict:
    """Independently verify an anchor by fetching the tx from Base.

    Returns verification result with calldata comparison.
    """
    w3 = get_web3()
    try:
        tx = w3.eth.get_transaction(tx_hash)
    except Exception as e:
        return {"tx_found": False, "error": str(e)}

    calldata_hex = tx.input.hex() if hasattr(tx.input, 'hex') else tx.input
    if calldata_hex.startswith("0x"):
        calldata_hex = calldata_hex[2:]

    block = w3.eth.get_block(tx.blockNumber)
    on_chain_root = "sha256:" + calldata_hex

    result = {
        "tx_found": True,
        "block_number": tx.blockNumber,
        "block_timestamp": block.timestamp,
        "merkle_root_on_chain": on_chain_root,
    }

    if expected_root:
        result["merkle_root_recorded"] = expected_root
        result["calldata_matches_recorded_root"] = (on_chain_root == expected_root)

    return result
