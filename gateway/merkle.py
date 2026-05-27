"""Merkle tree construction for receipt anchoring.

Uses merkle-sha256-v1 from the Receipt Chain Verification Protocol:
- Leaf: SHA256("BI_RECEIPT_LEAF_V1" || 0x00 || receipt_hash_bytes)
- Node: SHA256("BI_RECEIPT_NODE_V1" || 0x00 || left || right)
- Ordering: ascending seq
- Odd leaf: promote unchanged (no duplication)
"""

from __future__ import annotations

import hashlib

LEAF_DOMAIN = b"BI_RECEIPT_LEAF_V1"
NODE_DOMAIN = b"BI_RECEIPT_NODE_V1"


def leaf_hash(receipt_hash_hex: str) -> bytes:
    """Compute Merkle leaf hash from a receipt hash (hex, no prefix)."""
    return hashlib.sha256(LEAF_DOMAIN + b"\x00" + bytes.fromhex(receipt_hash_hex)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Compute Merkle internal node hash."""
    return hashlib.sha256(NODE_DOMAIN + b"\x00" + left + right).digest()


def compute_batch_root(receipt_hashes_hex: list[str]) -> str:
    """Compute batch root from ordered receipt hashes (hex, no prefix).

    Returns sha256:<hex> string.
    """
    if not receipt_hashes_hex:
        raise ValueError("Cannot compute batch root for empty batch")

    level = [leaf_hash(h) for h in receipt_hashes_hex]

    while len(level) > 1:
        next_level = []
        i = 0
        while i < len(level):
            if i + 1 < len(level):
                next_level.append(node_hash(level[i], level[i + 1]))
                i += 2
            else:
                next_level.append(level[i])
                i += 1
        level = next_level

    return "sha256:" + level[0].hex()
