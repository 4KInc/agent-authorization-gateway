"""Tests for the unified artifact log and Merkle anchoring.

Verifies:
1. ArtifactLog correctly appends and retrieves entries
2. compute_unified_root produces deterministic roots
3. compute_inclusion_proof generates valid proofs
4. Receipts are appended to the artifact log via the API
5. GET /artifacts/log returns entries
6. GET /artifacts/proof/{hash} returns valid inclusion proofs
"""

import os

os.environ["FIRESTORE_ENABLED"] = ""

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gateway.api import api_app, _get_gateway, _get_artifact_log
from gateway.artifact_log import ArtifactLog, compute_artifact_hash
from gateway.identity import create_agent_proof
from gateway.merkle import (
    compute_unified_root,
    compute_inclusion_proof,
    unified_leaf_hash,
    unified_node_hash,
)

client = TestClient(api_app)


# ── Unit tests: ArtifactLog ──────────────────────────────────────────

class TestArtifactLog:

    def test_append_increments_seq(self):
        log = ArtifactLog(tenant="test")
        e1 = log.append("receipt", "r1", "sha256:aaa", "kid-1")
        e2 = log.append("audit_report", "a1", "sha256:bbb", "kid-2")
        assert e1.seq == 1
        assert e2.seq == 2
        assert log.head_seq == 2

    def test_get_entries_since(self):
        log = ArtifactLog(tenant="test")
        for i in range(5):
            log.append("receipt", f"r{i}", f"sha256:{i:064x}", "kid")
        entries = log.get_entries_since(2)
        assert len(entries) == 3
        assert entries[0].seq == 3

    def test_get_all_hashes_since(self):
        log = ArtifactLog(tenant="test")
        log.append("receipt", "r1", "sha256:aaa", "kid")
        log.append("audit_report", "a1", "sha256:bbb", "kid")
        hashes = log.get_all_hashes_since(0)
        assert hashes == ["sha256:aaa", "sha256:bbb"]

    def test_get_entry(self):
        log = ArtifactLog(tenant="test")
        log.append("receipt", "r1", "sha256:aaa", "kid")
        entry = log.get_entry(1)
        assert entry is not None
        assert entry.artifact_id == "r1"
        assert log.get_entry(999) is None


# ── Unit tests: Merkle unified tree ──────────────────────────────────

class TestUnifiedMerkle:

    def test_single_leaf(self):
        root = compute_unified_root(["aa" * 32])
        assert root.startswith("sha256:")

    def test_deterministic(self):
        hashes = ["aa" * 32, "bb" * 32, "cc" * 32]
        r1 = compute_unified_root(hashes)
        r2 = compute_unified_root(hashes)
        assert r1 == r2

    def test_order_matters(self):
        h = ["aa" * 32, "bb" * 32]
        r1 = compute_unified_root(h)
        r2 = compute_unified_root(list(reversed(h)))
        assert r1 != r2

    def test_different_domain_from_receipt_tree(self):
        """Unified tree uses BI_ARTIFACT_* domain, not BI_RECEIPT_*."""
        from gateway.merkle import compute_batch_root
        hashes = ["aa" * 32, "bb" * 32]
        receipt_root = compute_batch_root(hashes)
        unified_root = compute_unified_root(hashes)
        assert receipt_root != unified_root

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            compute_unified_root([])


class TestInclusionProof:

    def test_proof_for_existing_leaf(self):
        hashes = ["aa" * 32, "bb" * 32, "cc" * 32, "dd" * 32]
        proof = compute_inclusion_proof(hashes, "cc" * 32)
        assert proof is not None
        assert proof["leaf_index"] == 2
        assert proof["tree_size"] == 4
        assert proof["root"] == compute_unified_root(hashes)
        assert len(proof["proof"]) > 0

    def test_proof_for_missing_leaf(self):
        hashes = ["aa" * 32, "bb" * 32]
        assert compute_inclusion_proof(hashes, "ff" * 32) is None

    def test_proof_verifies(self):
        """Manually verify an inclusion proof by recomputing the root."""
        hashes = ["aa" * 32, "bb" * 32, "cc" * 32, "dd" * 32]
        target = "bb" * 32
        proof = compute_inclusion_proof(hashes, target)

        # Start with the leaf hash
        current = unified_leaf_hash(target)

        # Walk up the proof path
        for step in proof["proof"]:
            sibling = bytes.fromhex(step["hash"])
            if step["direction"] == "right":
                current = unified_node_hash(current, sibling)
            else:
                current = unified_node_hash(sibling, current)

        recomputed_root = "sha256:" + current.hex()
        assert recomputed_root == proof["root"]
        assert recomputed_root == compute_unified_root(hashes)


# ── Integration tests: API endpoints ─────────────────────────────────

_agent_key = Ed25519PrivateKey.generate()
_agent_id = "artifact-test-agent"


def _make_jwk(key):
    pub_bytes = key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


def _register_agent():
    gw = _get_gateway()
    if gw._registry.get(_agent_id) is None:
        gw._registry.register(_agent_id, _make_jwk(_agent_key))


def test_receipt_appends_to_artifact_log():
    """POST /authorize should append a receipt to the artifact log."""
    from gateway import identity
    identity._proof_jti_cache.clear()
    _register_agent()

    art_log = _get_artifact_log()
    before = art_log.head_seq

    proof = create_agent_proof(_agent_key, _agent_id, "read", "staging-db")
    resp = client.post("/authorize", json={
        "agent_id": _agent_id,
        "action": "read",
        "resource": "staging-db",
        "agent_proof": proof,
    })
    assert resp.status_code == 200

    after = art_log.head_seq
    assert after > before


def test_artifact_log_endpoint():
    """GET /artifacts/log should return entries."""
    resp = client.get("/artifacts/log?limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert "entries" in data
    assert "head_seq" in data
    assert isinstance(data["entries"], list)


def test_artifact_proof_endpoint():
    """GET /artifacts/proof/{hash} should return a valid inclusion proof."""
    # First create a receipt to get an artifact hash
    from gateway import identity
    identity._proof_jti_cache.clear()
    _register_agent()

    proof_jwt = create_agent_proof(_agent_key, _agent_id, "read", "staging-db")
    resp = client.post("/authorize", json={
        "agent_id": _agent_id,
        "action": "read",
        "resource": "staging-db",
        "agent_proof": proof_jwt,
    })
    assert resp.status_code == 200
    receipt_hash = resp.json()["receipt_hash"]

    # Now request the inclusion proof
    proof_resp = client.get(f"/artifacts/proof/{receipt_hash}")
    assert proof_resp.status_code == 200
    proof_data = proof_resp.json()
    assert proof_data["artifact_hash"] == receipt_hash.removeprefix("sha256:")
    assert proof_data["artifact_type"] == "receipt"
    assert "root" in proof_data
    assert "proof" in proof_data


def test_artifact_proof_not_found():
    """GET /artifacts/proof/{fake} should return 404."""
    resp = client.get("/artifacts/proof/sha256:" + "ff" * 32)
    assert resp.status_code == 404
