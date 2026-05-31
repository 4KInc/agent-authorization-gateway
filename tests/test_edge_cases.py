"""Edge case tests — rate limiting, policy updates, adversarial inputs."""

import copy
import hashlib
import os
import time

os.environ["FIRESTORE_ENABLED"] = ""

import pytest

from gateway.gateway_service import GatewayService
from gateway.identity import AgentRegistry, create_agent_proof
from gateway.policy import Policy, PolicyRule, PolicyEngine, create_demo_policy
from gateway.verify import verify_receipt, verify_chain
from tests.helpers import make_jwk, make_registered_gateway, authorized_call

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class TestRateLimiting:
    def setup_method(self):
        from gateway import identity
        identity._proof_jti_cache.clear()
        policy = Policy(
            version="1",
            rules=[
                PolicyRule(id="rate", type="rate_limit", config={"max_actions": 3, "window_seconds": 60}),
            ],
        )
        registry = AgentRegistry()
        self.agent_key = Ed25519PrivateKey.generate()
        self.agent_id = "a1"
        registry.register(self.agent_id, make_jwk(self.agent_key))
        # Also register a2 for the separate-limits test
        self.agent_key2 = Ed25519PrivateKey.generate()
        registry.register("a2", make_jwk(self.agent_key2))
        self.gw = GatewayService(tenant="test", policy=policy, registry=registry)

    def test_allows_up_to_limit(self):
        for i in range(3):
            r = authorized_call(self.gw, self.agent_key, self.agent_id, "read", "db")
            assert r.decision == "approve", f"Request {i+1} should be approved"

    def test_blocks_after_limit(self):
        for _ in range(3):
            authorized_call(self.gw, self.agent_key, self.agent_id, "read", "db")
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "read", "db")
        assert r.decision == "deny"
        assert any("RATE_LIMIT_EXCEEDED" in code for code in r.reason_codes)

    def test_different_agents_have_separate_limits(self):
        for _ in range(3):
            authorized_call(self.gw, self.agent_key, self.agent_id, "read", "db")
        # a1 is now rate-limited, but a2 should still be allowed
        r = authorized_call(self.gw, self.agent_key2, "a2", "read", "db")
        assert r.decision == "approve"

    def test_rate_limit_receipt_still_signed(self):
        for _ in range(3):
            authorized_call(self.gw, self.agent_key, self.agent_id, "read", "db")
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "read", "db")
        assert r.decision == "deny"
        result = verify_receipt(r.receipt, self.gw.get_public_key_jwk())
        assert result.receipt_integrity == "PASS"


class TestPolicyUpdateMidChain:
    def test_chain_valid_across_policy_change(self):
        from gateway import identity
        identity._proof_jti_cache.clear()
        gw, agent_key, agent_id = make_registered_gateway()
        r1 = authorized_call(gw, agent_key, agent_id, "read", "staging-db")
        assert r1.decision == "approve"
        old_policy_hash = gw.policy.policy_hash()

        # Change policy to deny all resources
        gw.policy = Policy(version="2", rules=[
            PolicyRule(id="block_all", type="resource_scope", config={"allowed_resources": ["nonexistent"]}),
        ])
        gw._policy_engine = PolicyEngine(gw.policy)
        new_policy_hash = gw.policy.policy_hash()
        assert old_policy_hash != new_policy_hash

        r2 = authorized_call(gw, agent_key, agent_id, "read", "staging-db")
        assert r2.decision == "deny"

        chain = gw.get_receipt_chain()
        result = verify_chain(chain, gw.get_public_key_jwk())
        assert result.receipt_integrity == "PASS"
        assert result.chain_validity == "PASS"
        assert chain[0]["body"]["policy_version"] == old_policy_hash
        assert chain[1]["body"]["policy_version"] == new_policy_hash


class TestAdversarialInputs:
    def setup_method(self):
        from gateway import identity
        identity._proof_jti_cache.clear()
        self.gw, self.agent_key, self.agent_id = make_registered_gateway()

    def test_unicode_in_agent_id(self):
        # Register a unicode agent_id
        uid = "agent-\u00e9\u00e8\u00ea"
        key = Ed25519PrivateKey.generate()
        self.gw._registry.register(uid, make_jwk(key))
        r = authorized_call(self.gw, key, uid, "read", "staging-db")
        assert r.decision == "approve"
        result = verify_receipt(r.receipt, self.gw.get_public_key_jwk())
        assert result.receipt_integrity == "PASS"

    def test_very_long_action_string(self):
        # A very long action that doesn't exactly match any allowed action should
        # be denied, but the system must handle it gracefully (no crash, receipt
        # still signed). Allowlist uses exact match, so "read read read..." != "read".
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "read " * 1000, "staging-db")
        assert r.decision == "deny"
        assert any("ACTION_NOT_ALLOWED" in code for code in r.reason_codes)
        assert r.receipt_hash.startswith("sha256:")

    def test_empty_parameters(self):
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "read", "staging-db")
        assert r.decision == "approve"

    def test_nested_parameters(self):
        from gateway.tokens import compute_action_digest
        params = {"query": {"filter": {"status": "active"}, "limit": 100}}
        digest = compute_action_digest(self.agent_id, "read", "staging-db", params)
        proof = create_agent_proof(self.agent_key, self.agent_id, "read", "staging-db", action_digest=digest)
        r = self.gw.authorize(
            agent_id=self.agent_id, action="read", resource="staging-db",
            parameters=params, agent_proof=proof,
        )
        assert r.decision == "approve"
        result = verify_receipt(r.receipt, self.gw.get_public_key_jwk())
        assert result.receipt_integrity == "PASS"

    def test_special_chars_in_resource(self):
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "read", "staging/db:table@v2")
        assert r.decision == "approve"

    def test_tampered_signature_detected(self):
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "read", "staging-db")
        receipt = copy.deepcopy(r.receipt)
        sig = receipt["sig"]["value"]
        # Flip multiple characters in the middle to guarantee a different sig
        mid = len(sig) // 2
        tampered = sig[:mid-2] + "XXXX" + sig[mid+2:]
        receipt["sig"]["value"] = tampered
        result = verify_receipt(receipt, self.gw.get_public_key_jwk())
        assert result.receipt_integrity == "FAIL"

    def test_tampered_hash_detected(self):
        r = authorized_call(self.gw, self.agent_key, self.agent_id, "read", "staging-db")
        receipt = copy.deepcopy(r.receipt)
        receipt["receipt_hash"] = "sha256:" + "a" * 64
        result = verify_receipt(receipt, self.gw.get_public_key_jwk())
        assert result.receipt_integrity == "FAIL"

    def test_swapped_receipt_bodies_detected(self):
        r1 = authorized_call(self.gw, self.agent_key, self.agent_id, "read", "staging-db")
        r2 = authorized_call(self.gw, self.agent_key, self.agent_id, "query", "staging-db")
        receipt = copy.deepcopy(r1.receipt)
        receipt["body"] = r2.receipt["body"]
        result = verify_receipt(receipt, self.gw.get_public_key_jwk())
        assert result.receipt_integrity == "FAIL"


class TestChainEdgeCases:
    def setup_method(self):
        from gateway import identity
        identity._proof_jti_cache.clear()

    def test_empty_chain_returns_inconclusive(self):
        gw = GatewayService(tenant="test")
        result = verify_chain([], gw.get_public_key_jwk())
        assert result.receipt_integrity == "INCONCLUSIVE"
        assert result.chain_validity == "INCONCLUSIVE"

    def test_single_receipt_chain_valid(self):
        gw, key, aid = make_registered_gateway()
        authorized_call(gw, key, aid, "read", "staging-db")
        chain = gw.get_receipt_chain()
        result = verify_chain(chain, gw.get_public_key_jwk())
        assert result.receipt_integrity == "PASS"
        assert result.chain_validity == "PASS"

    def test_reversed_chain_fails(self):
        gw, key, aid = make_registered_gateway()
        for res in ["staging-db", "dev-db", "test-db"]:
            authorized_call(gw, key, aid, "read", res)
        chain = gw.get_receipt_chain()
        reversed_chain = list(reversed(chain))
        result = verify_chain(reversed_chain, gw.get_public_key_jwk())
        assert result.chain_validity == "FAIL" or result.receipt_integrity == "FAIL"

    def test_duplicate_receipt_in_chain_fails(self):
        gw, key, aid = make_registered_gateway()
        authorized_call(gw, key, aid, "read", "staging-db")
        chain = gw.get_receipt_chain()
        bad_chain = chain + chain
        result = verify_chain(bad_chain, gw.get_public_key_jwk())
        assert result.chain_validity == "FAIL" or result.receipt_integrity == "FAIL"

    def test_large_chain_verifies(self):
        gw, key, aid = make_registered_gateway()
        for i in range(20):
            authorized_call(gw, key, aid, "read", f"staging-db-{i}")
        chain = gw.get_receipt_chain()
        assert len(chain) == 20
        result = verify_chain(chain, gw.get_public_key_jwk())
        assert result.receipt_integrity == "PASS"
        assert result.chain_validity == "PASS"


class TestMerkleEdgeCases:
    def setup_method(self):
        from gateway import identity
        identity._proof_jti_cache.clear()

    def test_merkle_root_changes_with_new_receipt(self):
        gw, key, aid = make_registered_gateway()
        authorized_call(gw, key, aid, "read", "staging-db")
        root1 = gw.get_merkle_root()
        authorized_call(gw, key, aid, "read", "dev-db")
        root2 = gw.get_merkle_root()
        assert root1 != root2

    def test_merkle_root_none_for_empty_chain(self):
        gw = GatewayService(tenant="test")
        assert gw.get_merkle_root() is None

    def test_stats_counts_correct(self):
        gw, key, aid = make_registered_gateway()
        authorized_call(gw, key, aid, "read", "staging-db")    # approve
        authorized_call(gw, key, aid, "read", "dev-db")        # approve
        authorized_call(gw, key, aid, "delete", "production")  # deny
        stats = gw.get_chain_stats()
        assert stats["total_receipts"] == 3
        assert stats["approvals"] == 2
        assert stats["denials"] == 1
        assert stats["merkle_root"] is not None
