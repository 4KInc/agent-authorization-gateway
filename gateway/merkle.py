"""Merkle tree construction for tamper-evident anchoring.

Supports two modes:
1. Receipt-only (legacy): uses BI_RECEIPT_LEAF_V1 domain tag
2. Unified artifacts: uses BI_ARTIFACT_LEAF_V1 domain tag, covers
   receipts + audit reports + policy proposals + incident reports +
   isolation records in one tree

Both modes use:
- Leaf: SHA256(domain || 0x00 || hash_bytes)
- Node: SHA256(domain || 0x00 || left || right)
- Ordering: ascending by position in the input list
- Odd leaf: promote unchanged (no duplication)
"""

from __future__ import annotations

import hashlib

# Legacy domain tags (receipt-only anchoring)
LEAF_DOMAIN = b"BI_RECEIPT_LEAF_V1"
NODE_DOMAIN = b"BI_RECEIPT_NODE_V1"

# Unified domain tags (all signed artifacts)
UNIFIED_LEAF_DOMAIN = b"BI_ARTIFACT_LEAF_V1"
UNIFIED_NODE_DOMAIN = b"BI_ARTIFACT_NODE_V1"


def leaf_hash(receipt_hash_hex: str) -> bytes:
    """Compute Merkle leaf hash from a receipt hash (hex, no prefix)."""
    return hashlib.sha256(LEAF_DOMAIN + b"\x00" + bytes.fromhex(receipt_hash_hex)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Compute Merkle internal node hash."""
    return hashlib.sha256(NODE_DOMAIN + b"\x00" + left + right).digest()


def unified_leaf_hash(artifact_hash_hex: str) -> bytes:
    """Compute leaf hash for the unified artifact tree."""
    return hashlib.sha256(UNIFIED_LEAF_DOMAIN + b"\x00" + bytes.fromhex(artifact_hash_hex)).digest()


def unified_node_hash(left: bytes, right: bytes) -> bytes:
    """Compute internal node hash for the unified artifact tree."""
    return hashlib.sha256(UNIFIED_NODE_DOMAIN + b"\x00" + left + right).digest()


def _build_tree(leaves: list[bytes], node_fn) -> list[list[bytes]]:
    """Build a full Merkle tree from leaves. Returns all levels (leaves first)."""
    if not leaves:
        raise ValueError("Cannot build tree for empty leaf set")

    levels = [leaves]
    current = leaves

    while len(current) > 1:
        next_level = []
        i = 0
        while i < len(current):
            if i + 1 < len(current):
                next_level.append(node_fn(current[i], current[i + 1]))
                i += 2
            else:
                next_level.append(current[i])
                i += 1
        levels.append(next_level)
        current = next_level

    return levels


def compute_batch_root(receipt_hashes_hex: list[str]) -> str:
    """Compute batch root from ordered receipt hashes (hex, no prefix).

    Returns sha256:<hex> string. Legacy receipt-only mode.
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


def compute_unified_root(artifact_hashes_hex: list[str]) -> str:
    """Compute Merkle root over all artifact hashes (unified tree).

    Covers receipts, audit reports, policy proposals, incident reports,
    and isolation records in one tree. Returns sha256:<hex> string.
    """
    if not artifact_hashes_hex:
        raise ValueError("Cannot compute unified root for empty batch")

    leaves = [unified_leaf_hash(h) for h in artifact_hashes_hex]
    levels = _build_tree(leaves, unified_node_hash)
    root = levels[-1][0]
    return "sha256:" + root.hex()


def compute_inclusion_proof(
    artifact_hashes_hex: list[str],
    target_hash_hex: str,
) -> dict | None:
    """Compute a Merkle inclusion proof for a specific artifact.

    Returns a dict with the proof path (sibling hashes + directions)
    that allows a verifier to recompute the root from the leaf.
    Returns None if the target is not in the batch.
    """
    if target_hash_hex not in artifact_hashes_hex:
        return None

    target_index = artifact_hashes_hex.index(target_hash_hex)
    leaves = [unified_leaf_hash(h) for h in artifact_hashes_hex]
    levels = _build_tree(leaves, unified_node_hash)
    root = levels[-1][0]

    proof_path: list[dict] = []
    idx = target_index

    for level in levels[:-1]:  # skip root level
        if idx % 2 == 0:
            # Target is left child; sibling is right
            if idx + 1 < len(level):
                proof_path.append({"hash": level[idx + 1].hex(), "direction": "right"})
        else:
            # Target is right child; sibling is left
            proof_path.append({"hash": level[idx - 1].hex(), "direction": "left"})
        idx //= 2

    return {
        "artifact_hash": target_hash_hex,
        "leaf_index": target_index,
        "tree_size": len(artifact_hashes_hex),
        "root": "sha256:" + root.hex(),
        "proof": proof_path,
    }
