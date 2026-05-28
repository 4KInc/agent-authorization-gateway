"""Comprehensive tests for the Agent Authorization Gateway.

Covers: authorization flow, receipt signing, chain verification,
token issuance, Merkle tree, and canonical JSON.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway.canonical import canonicalize
from gateway.gateway_service import GatewayService
from gateway.merkle import compute_batch_root, leaf_hash, node_hash
from gateway.policy import Policy, PolicyEngine, PolicyRule, create_demo_policy
from gateway.receipts import GENESIS_PREV_RECEIPT, Receipt, ReceiptChain
from gateway.tokens import compute_action_digest, issue_token, verify_token
from gateway.verify import verify_chain, verify_receipt


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def gateway() -> GatewayService:
    """A GatewayService with the default demo policy."""
    return GatewayService(tenant="test-tenant")


@pytest.fixture
def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def receipt_chain(signing_key: Ed25519PrivateKey) -> ReceiptChain:
    return ReceiptChain(
        tenant="test-tenant",
        private_key=signing_key,
        kid="test-kid-001",
    )


# ===========================================================================
# 1. Authorization Flow
# ===========================================================================

class TestAuthorizationFlow:
    """Tests for the end-to-end authorize() pipeline."""

    def test_approve_agent_reading_staging_database(self, gateway: GatewayService):
        """agent-1 reading from staging-database should be allowed."""
        resp = gateway.authorize(
            agent_id="agent-1",
            action="read",
            resource="staging-database",
        )
        assert resp.decision == "approve"
        assert resp.reason_codes == []

    def test_deny_rogue_agent_deleting_production(self, gateway: GatewayService):
        """rogue-agent deleting from db:production must be blocked."""
        resp = gateway.authorize(
            agent_id="rogue-agent",
            action="delete",
            resource="db:production",
        )
        assert resp.decision == "deny"
        assert any("ACTION_NOT_ALLOWED" in r for r in resp.reason_codes)
        assert any("RESOURCE_OUT_OF_SCOPE" in r for r in resp.reason_codes)

    def test_deny_action_not_in_allowed_list(self, gateway: GatewayService):
        """An action not in the allowlist should be denied."""
        resp = gateway.authorize(
            agent_id="agent-1",
            action="drop-table",
            resource="staging-database",
        )
        assert resp.decision == "deny"
        assert any("ACTION_NOT_ALLOWED" in r for r in resp.reason_codes)

    def test_deny_resource_out_of_scope(self, gateway: GatewayService):
        """A read on a production resource should be denied."""
        resp = gateway.authorize(
            agent_id="agent-1",
            action="read",
            resource="production-secrets",
        )
        assert resp.decision == "deny"
        assert any("RESOURCE_OUT_OF_SCOPE" in r for r in resp.reason_codes)

    def test_approve_returns_token_deny_returns_none(self, gateway: GatewayService):
        """Approved requests get a JWT token; denied requests get None."""
        approved = gateway.authorize("agent-1", "read", "staging-db")
        denied = gateway.authorize("rogue-agent", "delete", "db:production")

        assert approved.token is not None
        assert isinstance(approved.token, str)
        assert denied.token is None


# ===========================================================================
# 2. Receipt Signing
# ===========================================================================

class TestReceiptSigning:
    """Tests for receipt structure, hashing, and signature validity."""

    def test_receipt_has_correct_body_structure(
        self, receipt_chain: ReceiptChain
    ):
        """Receipt body must contain exactly the 9 canonical fields."""
        receipt = receipt_chain.sign_decision(
            request_digest="sha256:aabbccdd",
            policy_version="sha256:00112233",
            decision="approve",
            reasons=[],
        )
        body = receipt.body_dict()
        expected_keys = {
            "v", "tenant", "seq", "ts",
            "request_digest", "policy_version",
            "decision", "reasons", "prev_receipt",
        }
        assert set(body.keys()) == expected_keys

    def test_receipt_hash_matches_sha256_of_canonical_body(
        self, receipt_chain: ReceiptChain
    ):
        """receipt_hash must equal sha256:<hex> of the canonicalized body."""
        receipt = receipt_chain.sign_decision(
            request_digest="sha256:aabbccdd",
            policy_version="sha256:00112233",
            decision="approve",
            reasons=[],
        )
        body_bytes = canonicalize(receipt.body_dict())
        expected_hash = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
        assert receipt.receipt_hash == expected_hash

    def test_ed25519_signature_is_valid(
        self, receipt_chain: ReceiptChain, signing_key: Ed25519PrivateKey
    ):
        """The Ed25519 signature must verify against the public key."""
        receipt = receipt_chain.sign_decision(
            request_digest="sha256:aabbccdd",
            policy_version="sha256:00112233",
            decision="deny",
            reasons=["RATE_LIMIT_EXCEEDED:rl1"],
        )
        body_bytes = canonicalize(receipt.body_dict())

        # Decode the base64url signature
        sig_padded = receipt.signature + "=" * (4 - len(receipt.signature) % 4)
        sig_bytes = base64.urlsafe_b64decode(sig_padded)

        # This should not raise
        signing_key.public_key().verify(sig_bytes, body_bytes)

    def test_seq_numbers_are_monotonically_increasing(
        self, receipt_chain: ReceiptChain
    ):
        """Successive receipts must have monotonically increasing seq values."""
        seqs = []
        for i in range(5):
            r = receipt_chain.sign_decision(
                request_digest=f"sha256:{i:064x}",
                policy_version="sha256:policy",
                decision="approve",
                reasons=[],
            )
            seqs.append(int(r.seq))

        assert seqs == [1, 2, 3, 4, 5]


# ===========================================================================
# 3. Chain Verification
# ===========================================================================

class TestChainVerification:
    """Tests for verify_chain and verify_receipt."""

    def _build_chain_envelopes(
        self, chain: ReceiptChain, count: int = 3
    ) -> list[dict]:
        """Helper: build a chain of `count` receipts and return envelopes."""
        for i in range(count):
            chain.sign_decision(
                request_digest=f"sha256:{i:064x}",
                policy_version="sha256:policyv1",
                decision="approve",
                reasons=[],
            )
        return [r.envelope_dict() for r in chain.get_receipts()]

    def _make_jwk(self, key: Ed25519PrivateKey, kid: str) -> dict:
        pub_bytes = key.public_key().public_bytes_raw()
        x_b64url = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": kid,
            "use": "sig",
            "alg": "EdDSA",
            "x": x_b64url,
        }

    def test_valid_chain_passes_verification(
        self, receipt_chain: ReceiptChain, signing_key: Ed25519PrivateKey
    ):
        """A properly constructed chain should pass all checks."""
        envelopes = self._build_chain_envelopes(receipt_chain)
        jwk = self._make_jwk(signing_key, "test-kid-001")
        result = verify_chain(envelopes, jwk)
        assert result.receipt_integrity == "PASS"
        assert result.chain_validity == "PASS"
        assert result.errors == []

    def test_tampered_body_fails_verification(
        self, receipt_chain: ReceiptChain, signing_key: Ed25519PrivateKey
    ):
        """Modifying a receipt body after signing must fail verification."""
        envelopes = self._build_chain_envelopes(receipt_chain)
        jwk = self._make_jwk(signing_key, "test-kid-001")

        # Tamper with the second receipt's decision
        envelopes[1]["body"]["decision"] = "tampered"

        result = verify_chain(envelopes, jwk)
        assert result.receipt_integrity == "FAIL" or result.chain_validity == "FAIL"
        assert len(result.errors) > 0

    def test_missing_receipt_in_sequence_detected(
        self, receipt_chain: ReceiptChain, signing_key: Ed25519PrivateKey
    ):
        """Removing a receipt from the middle of the chain must be detected."""
        envelopes = self._build_chain_envelopes(receipt_chain, count=4)
        jwk = self._make_jwk(signing_key, "test-kid-001")

        # Remove the second receipt (seq 2), leaving a gap 1 -> 3
        del envelopes[1]

        result = verify_chain(envelopes, jwk)
        assert result.chain_validity == "FAIL"
        assert any("SEQUENCE_GAP" in e.get("code", "") or "CHAIN_BREAK" in e.get("code", "")
                    for e in result.errors)

    def test_genesis_prev_receipt_is_null_hash(
        self, receipt_chain: ReceiptChain, signing_key: Ed25519PrivateKey
    ):
        """The first receipt's prev_receipt must be the genesis null hash."""
        receipt_chain.sign_decision(
            request_digest="sha256:first",
            policy_version="sha256:pv",
            decision="approve",
            reasons=[],
        )
        envelopes = [r.envelope_dict() for r in receipt_chain.get_receipts()]
        jwk = self._make_jwk(signing_key, "test-kid-001")

        assert envelopes[0]["body"]["prev_receipt"] == GENESIS_PREV_RECEIPT

        result = verify_chain(envelopes, jwk)
        assert result.receipt_integrity == "PASS"
        assert result.chain_validity == "PASS"


# ===========================================================================
# 4. Token Issuance
# ===========================================================================

class TestTokenIssuance:
    """Tests for JWT token generation and claims (Ed25519/EdDSA)."""

    def test_token_has_correct_claims(self):
        """Issued token must contain agent_id, action, resource, action_digest, and exp."""
        private_key = Ed25519PrivateKey.generate()
        agent_id = "agent-42"
        action_digest = "sha256:deadbeef"
        receipt_hash = "sha256:cafebabe"

        token, jti = issue_token(
            private_key=private_key,
            agent_id=agent_id,
            action="read",
            resource="staging-db",
            action_digest=action_digest,
            decision="approve",
            receipt_hash=receipt_hash,
            tenant="test",
        )

        decoded = jwt.decode(
            token, private_key.public_key(), algorithms=["EdDSA"],
            audience="protected-resource",
        )
        assert decoded["sub"] == agent_id
        assert decoded["action"] == "read"
        assert decoded["resource"] == "staging-db"
        assert decoded["action_digest"] == action_digest
        assert "exp" in decoded
        assert decoded["decision"] == "approve"
        assert decoded["receipt_hash"] == receipt_hash
        assert decoded["tid"] == "test"
        assert decoded["iss"] == "agent-authorization-gateway"
        assert decoded["jti"] == jti

    def test_token_expires_after_60_seconds(self):
        """Token exp claim must be ~60 seconds after iat."""
        private_key = Ed25519PrivateKey.generate()
        token, jti = issue_token(
            private_key=private_key,
            agent_id="agent-1",
            action="read",
            resource="db",
            action_digest="sha256:abc",
            decision="approve",
            receipt_hash="sha256:def",
        )
        decoded = jwt.decode(
            token, private_key.public_key(), algorithms=["EdDSA"],
            audience="protected-resource",
        )
        ttl = decoded["exp"] - decoded["iat"]
        assert ttl == 60


# ===========================================================================
# 5. Merkle Tree
# ===========================================================================

class TestMerkleTree:
    """Tests for Merkle batch root computation."""

    def test_single_receipt_produces_correct_root(self):
        """A single receipt hash should produce root = leaf_hash of that receipt."""
        h = "a" * 64  # valid hex string
        root = compute_batch_root([h])
        expected = "sha256:" + leaf_hash(h).hex()
        assert root == expected

    def test_multiple_receipts_produce_deterministic_root(self):
        """The same set of receipt hashes must always produce the same root."""
        hashes = [f"{i:064x}" for i in range(5)]
        root1 = compute_batch_root(hashes)
        root2 = compute_batch_root(hashes)
        assert root1 == root2
        assert root1.startswith("sha256:")

    def test_different_hashes_produce_different_root(self):
        """Changing one input hash must change the Merkle root."""
        hashes_a = [f"{i:064x}" for i in range(4)]
        hashes_b = list(hashes_a)
        hashes_b[2] = "ff" * 32
        root_a = compute_batch_root(hashes_a)
        root_b = compute_batch_root(hashes_b)
        assert root_a != root_b


# ===========================================================================
# 6. Canonical JSON
# ===========================================================================

class TestCanonicalJson:
    """Tests for JCS-subset canonical JSON serialization."""

    def test_keys_are_sorted_deterministically(self):
        """Object keys must be sorted per JCS (RFC 8785) rules."""
        obj = {"z": 1, "a": 2, "m": 3}
        result = canonicalize(obj).decode("utf-8")
        assert result == '{"a":2,"m":3,"z":1}'

    def test_same_data_same_bytes_regardless_of_insertion_order(self):
        """Two dicts with the same data but different insertion order must
        produce identical canonical bytes."""
        obj1 = {"action": "read", "agent_id": "a1", "resource": "staging"}
        obj2 = {"resource": "staging", "action": "read", "agent_id": "a1"}
        assert canonicalize(obj1) == canonicalize(obj2)

    def test_nested_objects_are_canonicalized(self):
        """Nested dicts and lists should also be canonicalized."""
        obj = {"b": [3, 2, 1], "a": {"z": 0, "y": 1}}
        result = canonicalize(obj).decode("utf-8")
        assert result == '{"a":{"y":1,"z":0},"b":[3,2,1]}'
