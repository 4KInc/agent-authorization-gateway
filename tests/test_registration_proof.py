"""Tests for Agent Proof of Possession at Registration."""

import base64
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway.identity import (
    AgentRegistry,
    RegistrationChallengeCache,
    build_registration_message,
    verify_registration_proof,
)


def _make_keypair():
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": x}
    return priv, jwk


def _sign_challenge(priv_key, tenant, agent_id, jwk, nonce, challenge_id, iat=None):
    if iat is None:
        iat = int(time.time())
    message = build_registration_message(tenant, agent_id, jwk, nonce, challenge_id, iat)
    sig = priv_key.sign(message)
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return {"nonce": nonce, "challenge_id": challenge_id, "signature": sig_b64, "iat": iat}


TENANT = "test-tenant"
AGENT_ID = "test-agent-01"


class TestChallengeCache:
    def test_issue_and_consume(self):
        cache = RegistrationChallengeCache(ttl_seconds=60)
        ch = cache.issue(TENANT, AGENT_ID)
        assert "nonce" in ch and "challenge_id" in ch
        valid, err = cache.consume(TENANT, AGENT_ID, ch["nonce"], ch["challenge_id"])
        assert valid and err == ""

    def test_unknown_nonce(self):
        cache = RegistrationChallengeCache()
        valid, err = cache.consume(TENANT, AGENT_ID, "bogus", "bogus")
        assert not valid and err == "CHALLENGE_NOT_FOUND"

    def test_replay_rejected(self):
        cache = RegistrationChallengeCache()
        ch = cache.issue(TENANT, AGENT_ID)
        cache.consume(TENANT, AGENT_ID, ch["nonce"], ch["challenge_id"])
        valid, err = cache.consume(TENANT, AGENT_ID, ch["nonce"], ch["challenge_id"])
        assert not valid and err == "CHALLENGE_NOT_FOUND"

    def test_expired_nonce(self):
        cache = RegistrationChallengeCache(ttl_seconds=0)
        ch = cache.issue(TENANT, AGENT_ID)
        time.sleep(0.01)
        valid, err = cache.consume(TENANT, AGENT_ID, ch["nonce"], ch["challenge_id"])
        assert not valid

    def test_wrong_challenge_id(self):
        cache = RegistrationChallengeCache()
        ch = cache.issue(TENANT, AGENT_ID)
        valid, err = cache.consume(TENANT, AGENT_ID, ch["nonce"], "wrong")
        assert not valid and err == "CHALLENGE_ID_MISMATCH"

    def test_tenant_isolation(self):
        cache = RegistrationChallengeCache()
        ch = cache.issue("tenant-a", AGENT_ID)
        valid, err = cache.consume("tenant-b", AGENT_ID, ch["nonce"], ch["challenge_id"])
        assert not valid and err == "CHALLENGE_NOT_FOUND"


class TestRegistrationProof:
    def test_valid_proof(self):
        priv, jwk = _make_keypair()
        cache = RegistrationChallengeCache()
        ch = cache.issue(TENANT, AGENT_ID)
        proof = _sign_challenge(priv, TENANT, AGENT_ID, jwk, ch["nonce"], ch["challenge_id"])
        valid, err = verify_registration_proof(jwk, proof, TENANT, AGENT_ID, cache)
        assert valid and err == ""

    def test_no_proof(self):
        cache = RegistrationChallengeCache()
        valid, err = verify_registration_proof({}, None, TENANT, AGENT_ID, cache)
        assert not valid and err == "NO_PROOF"

    def test_empty_proof(self):
        cache = RegistrationChallengeCache()
        valid, err = verify_registration_proof({}, {}, TENANT, AGENT_ID, cache)
        assert not valid and err == "NO_PROOF"

    def test_missing_fields(self):
        cache = RegistrationChallengeCache()
        _, jwk = _make_keypair()
        valid, err = verify_registration_proof(jwk, {"nonce": "x"}, TENANT, AGENT_ID, cache)
        assert not valid and err == "INVALID_PROOF_FORMAT"

    def test_invalid_signature(self):
        priv, jwk = _make_keypair()
        other_priv, _ = _make_keypair()
        cache = RegistrationChallengeCache()
        ch = cache.issue(TENANT, AGENT_ID)
        proof = _sign_challenge(other_priv, TENANT, AGENT_ID, jwk, ch["nonce"], ch["challenge_id"])
        valid, err = verify_registration_proof(jwk, proof, TENANT, AGENT_ID, cache)
        assert not valid and err == "INVALID_PROOF_SIGNATURE"

    def test_different_key_than_registered(self):
        priv_a, jwk_a = _make_keypair()
        priv_b, jwk_b = _make_keypair()
        cache = RegistrationChallengeCache()
        ch = cache.issue(TENANT, AGENT_ID)
        proof = _sign_challenge(priv_b, TENANT, AGENT_ID, jwk_a, ch["nonce"], ch["challenge_id"])
        valid, err = verify_registration_proof(jwk_a, proof, TENANT, AGENT_ID, cache)
        assert not valid and err == "INVALID_PROOF_SIGNATURE"

    def test_expired_iat(self):
        priv, jwk = _make_keypair()
        cache = RegistrationChallengeCache()
        ch = cache.issue(TENANT, AGENT_ID)
        proof = _sign_challenge(priv, TENANT, AGENT_ID, jwk, ch["nonce"], ch["challenge_id"], iat=int(time.time()) - 120)
        valid, err = verify_registration_proof(jwk, proof, TENANT, AGENT_ID, cache)
        assert not valid and err == "PROOF_EXPIRED"

    def test_challenge_not_found(self):
        priv, jwk = _make_keypair()
        cache = RegistrationChallengeCache()
        proof = _sign_challenge(priv, TENANT, AGENT_ID, jwk, "fake", "fake")
        valid, err = verify_registration_proof(jwk, proof, TENANT, AGENT_ID, cache)
        assert not valid and err == "CHALLENGE_NOT_FOUND"


class TestRegistryReplaceSemantics:
    def test_replace_existing_agent(self):
        registry = AgentRegistry()
        _, jwk1 = _make_keypair()
        _, jwk2 = _make_keypair()
        agent1 = registry.register("agent-x", jwk1)
        agent2 = registry.register("agent-x", jwk2)
        assert agent1.kid != agent2.kid
        assert registry.get("agent-x").kid == agent2.kid

    def test_same_key_same_kid(self):
        registry = AgentRegistry()
        _, jwk = _make_keypair()
        agent1 = registry.register("agent-y", jwk)
        agent2 = registry.register("agent-y", jwk)
        assert agent1.kid == agent2.kid


class TestCanonicalMessageConsistency:
    def test_jcs_matches(self):
        from gateway.canonical import canonicalize
        _, jwk = _make_keypair()
        msg = build_registration_message("t", "a", jwk, "n", "c", 1700000000)
        expected = canonicalize({"v": "1", "tenant_id": "t", "agent_id": "a", "public_key": jwk, "nonce": "n", "challenge_id": "c", "iat": 1700000000})
        assert msg == expected
