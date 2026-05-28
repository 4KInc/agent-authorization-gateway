"""Edge case tests — rate limiting, policy updates, adversarial inputs."""

import copy
import hashlib
import os
import time

os.environ["FIRESTORE_ENABLED"] = ""

import pytest

from gateway.gateway_service import GatewayService
from gateway.policy import Policy, PolicyRule, PolicyEngine, create_demo_policy
from gateway.verify import verify_receipt, verify_chain


class TestRateLimiting:
    def setup_method(self):
        policy = Policy(
            version="1",
            rules=[
                PolicyRule(id="rate", type="rate_limit", config={"max_actions": 3, "window_seconds": 60}),
            ],
        )
        self.gw = GatewayService(tenant="test", policy=policy)

    def test_allows_up_to_limit(self):
        for i in range(3):
            r = self.gw.authorize(agent_id="a1", action="read", resource="db")
            assert r.decision == "approve", f"Request {i+1} should be approved"

    def test_blocks_after_limit(self):
        for _ in range(3):
            self.gw.authorize(agent_id="a1", action="read", resource="db")
        r = self.gw.authorize(agent_id="a1", action="read", resource="db")
        assert r.decision == "deny"
        assert any("RATE_LIMIT_EXCEEDED" in code for code in r.reason_codes)

    def test_different_agents_have_separate_limits(self):
        for _ in range(3):
            self.gw.authorize(agent_id="a1", action="read", resource="db")
        # a1 is now rate-limited, but a2 should still be allowed
        r = self.gw.authorize(agent_id="a2", action="read", resource="db")
        assert r.decision == "approve"

    def test_rate_limit_receipt_still_signed(self):
        for _ in range(3):
            self.gw.authorize(agent_id="a1", action="read", resource="db")
        r = self.gw.authorize(agent_id="a1", action="read", resource="db")
        assert r.decision == "deny"
        # Even denials produce valid receipts
        result = verify_receipt(r.receipt, self.gw.get_public_key_jwk())
        assert result.receipt_integrity == "PASS"


class TestPolicyUpdateMidChain:
    def test_chain_valid_across_policy_change(self):
        gw = GatewayService(tenant="test")
        # Authorize under policy v1
        r1 = gw.authorize(agent_id="a1", action="read", resource="staging-db")
        assert r1.decision == "approve"
        old_policy_hash = gw.policy.policy_hash()

        # Change policy to deny all resources (block everything)
        gw.policy = Policy(version="2", rules=[
            PolicyRule(id="block_all", type="resource_scope", config={"allowed_resources": ["nonexistent"]}),
        ])
        gw._policy_engine = PolicyEngine(gw.policy)
        new_policy_hash = gw.policy.policy_hash()
        assert old_policy_hash != new_policy_hash

        # Authorize under policy v2 — should be denied
        r2 = gw.authorize(agent_id="a1", action="read", resource="staging-db")
        assert r2.decision == "deny"

        # Chain should still verify (different policy versions are fine)
        chain = gw.get_receipt_chain()
        result = verify_chain(chain, gw.get_public_key_jwk())
        assert result.receipt_integrity == "PASS"
        assert result.chain_validity == "PASS"

        # Receipts should reference different policy versions
        assert chain[0]["body"]["policy_version"] == old_policy_hash
        assert chain[1]["body"]["policy_version"] == new_policy_hash


class TestAdversarialInputs:
    def setup_method(self):
        self.gw = GatewayService(tenant="test")

    def test_unicode_in_agent_id(self):
        r = self.gw.authorize(agent_id="agent-\u00e9\u00e8\u00ea", action="read", resource="staging-db")
        assert r.decision == "approve"
        result = verify_receipt(r.receipt, self.gw.get_public_key_jwk())
        assert result.receipt_integrity == "PASS"

    def test_very_long_action_string(self):
        r = self.gw.authorize(agent_id="a1", action="read " * 1000, resource="staging-db")
        assert r.decision == "approve"  # "read" is in the action string
        assert r.receipt_hash.startswith("sha256:")

    def test_empty_parameters(self):
        r = self.gw.authorize(agent_id="a1", action="read", resource="staging-db", parameters={})
        assert r.decision == "approve"

    def test_nested_parameters(self):
        params = {"query": {"filter": {"status": "active"}, "limit": 100}}
        r = self.gw.authorize(agent_id="a1", action="read", resource="staging-db", parameters=params)
        assert r.decision == "approve"
        result = verify_receipt(r.receipt, self.gw.get_public_key_jwk())
        assert result.receipt_integrity == "PASS"

    def test_special_chars_in_resource(self):
        r = self.gw.authorize(agent_id="a1", action="read", resource="staging/db:table@v2")
        assert r.decision == "approve"

    def test_tampered_signature_detected(self):
        r = self.gw.authorize(agent_id="a1", action="read", resource="staging-db")
        receipt = copy.deepcopy(r.receipt)
        # Tamper with the signature (flip a character)
        sig = receipt["sig"]["value"]
        receipt["sig"]["value"] = sig[:-1] + ("A" if sig[-1] != "A" else "B")
        result = verify_receipt(receipt, self.gw.get_public_key_jwk())
        assert result.receipt_integrity == "FAIL"

    def test_tampered_hash_detected(self):
        r = self.gw.authorize(agent_id="a1", action="read", resource="staging-db")
        receipt = copy.deepcopy(r.receipt)
        receipt["receipt_hash"] = "sha256:" + "a" * 64
        result = verify_receipt(receipt, self.gw.get_public_key_jwk())
        assert result.receipt_integrity == "FAIL"

    def test_swapped_receipt_bodies_detected(self):
        r1 = self.gw.authorize(agent_id="a1", action="read", resource="staging-db")
        r2 = self.gw.authorize(agent_id="a2", action="query", resource="staging-db")
        # Swap bodies but keep original signatures
        receipt = copy.deepcopy(r1.receipt)
        receipt["body"] = r2.receipt["body"]
        result = verify_receipt(receipt, self.gw.get_public_key_jwk())
        assert result.receipt_integrity == "FAIL"


class TestChainEdgeCases:
    def test_empty_chain_returns_inconclusive(self):
        gw = GatewayService(tenant="test")
        result = verify_chain([], gw.get_public_key_jwk())
        assert result.receipt_integrity == "INCONCLUSIVE"
        assert result.chain_validity == "INCONCLUSIVE"

    def test_single_receipt_chain_valid(self):
        gw = GatewayService(tenant="test")
        gw.authorize(agent_id="a1", action="read", resource="staging-db")
        chain = gw.get_receipt_chain()
        result = verify_chain(chain, gw.get_public_key_jwk())
        assert result.receipt_integrity == "PASS"
        assert result.chain_validity == "PASS"

    def test_reversed_chain_fails(self):
        gw = GatewayService(tenant="test")
        for i in range(3):
            gw.authorize(agent_id=f"a{i}", action="read", resource="staging-db")
        chain = gw.get_receipt_chain()
        reversed_chain = list(reversed(chain))
        result = verify_chain(reversed_chain, gw.get_public_key_jwk())
        # Should fail — reversed order breaks sequence and prev_receipt linkage
        assert result.chain_validity == "FAIL" or result.receipt_integrity == "FAIL"

    def test_duplicate_receipt_in_chain_fails(self):
        gw = GatewayService(tenant="test")
        gw.authorize(agent_id="a1", action="read", resource="staging-db")
        chain = gw.get_receipt_chain()
        # Duplicate the first receipt
        bad_chain = chain + chain
        result = verify_chain(bad_chain, gw.get_public_key_jwk())
        assert result.chain_validity == "FAIL" or result.receipt_integrity == "FAIL"

    def test_large_chain_verifies(self):
        gw = GatewayService(tenant="test")
        for i in range(20):
            gw.authorize(agent_id=f"agent-{i % 5}", action="read", resource="staging-db")
        chain = gw.get_receipt_chain()
        assert len(chain) == 20
        result = verify_chain(chain, gw.get_public_key_jwk())
        assert result.receipt_integrity == "PASS"
        assert result.chain_validity == "PASS"


class TestMerkleEdgeCases:
    def test_merkle_root_changes_with_new_receipt(self):
        gw = GatewayService(tenant="test")
        gw.authorize(agent_id="a1", action="read", resource="staging-db")
        root1 = gw.get_merkle_root()
        gw.authorize(agent_id="a2", action="read", resource="staging-db")
        root2 = gw.get_merkle_root()
        assert root1 != root2

    def test_merkle_root_none_for_empty_chain(self):
        gw = GatewayService(tenant="test")
        assert gw.get_merkle_root() is None

    def test_stats_counts_correct(self):
        gw = GatewayService(tenant="test")
        gw.authorize(agent_id="a1", action="read", resource="staging-db")  # approve
        gw.authorize(agent_id="a1", action="read", resource="staging-db")  # approve
        gw.authorize(agent_id="a1", action="delete", resource="production")  # deny
        stats = gw.get_chain_stats()
        assert stats["total_receipts"] == 3
        assert stats["approvals"] == 2
        assert stats["denials"] == 1
        assert stats["merkle_root"] is not None
