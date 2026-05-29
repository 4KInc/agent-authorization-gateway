"""Agent identity verification — DPoP-style proof of possession.

Each Worker agent has a long-lived Ed25519 keypair (the agent's identity).
Before authorizing, the agent must prove it holds the private key by
signing a DPoP-style proof (RFC 9449 inspired).

Flow:
1. Agent generates Ed25519 keypair
2. Agent registers public key with Gateway → gets agent_id
3. Every authorize_action call includes a signed proof JWT
4. Gateway verifies the proof before evaluating policy
5. Receipt includes the verified agent_id and the agent's key fingerprint

This prevents identity spoofing: a compromised agent cannot impersonate
another agent because it doesn't hold the other agent's private key.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

logger = logging.getLogger("gateway.identity")

# Replay cache for proof JTIs
_proof_jti_cache: dict[str, float] = {}
_PROOF_JTI_MAX = 5000
_PROOF_MAX_AGE = 30  # proofs must be created within last 30 seconds


@dataclass
class RegisteredAgent:
    """A registered agent with a verified identity."""
    agent_id: str
    public_key: Ed25519PublicKey
    kid: str  # key fingerprint
    registered_at: float = field(default_factory=time.time)


class AgentRegistry:
    """In-memory registry of agent identities.

    In production, this would be backed by Firestore or another
    persistent store. For the hackathon, in-memory is sufficient
    because agents re-register on startup.
    """

    def __init__(self):
        self._agents: dict[str, RegisteredAgent] = {}
        # Also index by kid for fast lookup
        self._by_kid: dict[str, RegisteredAgent] = {}

    def register(self, agent_id: str, public_key_jwk: dict) -> RegisteredAgent:
        """Register an agent's public key. Returns the registered agent."""
        # Parse the JWK
        x = public_key_jwk.get("x", "")
        x_padded = x.replace("-", "+").replace("_", "/")
        padding = 4 - len(x_padded) % 4
        if padding != 4:
            x_padded += "=" * padding
        key_bytes = base64.b64decode(x_padded)
        public_key = Ed25519PublicKey.from_public_bytes(key_bytes)

        # Compute key fingerprint
        kid = "agent-" + hashlib.sha256(key_bytes).hexdigest()[:16]

        agent = RegisteredAgent(
            agent_id=agent_id,
            public_key=public_key,
            kid=kid,
        )
        self._agents[agent_id] = agent
        self._by_kid[kid] = agent
        logger.info(f"Registered agent: {agent_id} kid={kid}")
        return agent

    def get(self, agent_id: str) -> RegisteredAgent | None:
        return self._agents.get(agent_id)

    def get_by_kid(self, kid: str) -> RegisteredAgent | None:
        return self._by_kid.get(kid)

    def list_agents(self) -> list[dict]:
        return [
            {"agent_id": a.agent_id, "kid": a.kid, "registered_at": a.registered_at}
            for a in self._agents.values()
        ]


def create_agent_proof(
    private_key: Ed25519PrivateKey,
    agent_id: str,
    action: str,
    resource: str,
    action_digest: str | None = None,
    gateway_url: str = "agent-authorization-gateway",
) -> str:
    """Create a DPoP-style proof JWT signed by the agent's private key.

    The proof binds the agent's identity to a specific action request,
    preventing replay and cross-action attacks.

    action_digest is ALWAYS included. If not provided explicitly, it is
    auto-computed from (agent_id, action, resource) using the same algorithm
    as the gateway (canonicalize + SHA-256). This ensures proofs always
    carry the mandatory digest binding.
    """
    if action_digest is None:
        from .tokens import compute_action_digest
        action_digest = compute_action_digest(agent_id, action, resource)

    now = time.time()
    payload = {
        "sub": agent_id,
        "htm": "POST",  # HTTP method
        "htu": gateway_url,  # target URL
        "action": action,
        "resource": resource,
        "jti": str(uuid.uuid4()),
        "iat": int(now),
        "action_digest": action_digest,
    }
    return jwt.encode(payload, private_key, algorithm="EdDSA")


def verify_agent_proof(
    proof: str,
    registry: AgentRegistry,
    expected_agent_id: str,
    expected_action: str,
    expected_resource: str,
    expected_action_digest: str | None = None,
) -> RegisteredAgent:
    """Verify a DPoP-style agent proof.

    Returns the verified RegisteredAgent on success.
    Raises ValueError with specific error on failure.
    """
    global _proof_jti_cache

    # Decode header to get the algorithm (without verification first)
    try:
        header = jwt.get_unverified_header(proof)
        unverified = jwt.decode(proof, options={"verify_signature": False})
    except jwt.InvalidTokenError as e:
        raise ValueError(f"INVALID_PROOF: malformed proof JWT: {e}")

    # Look up the agent
    agent_id = unverified.get("sub", "")
    if agent_id != expected_agent_id:
        raise ValueError(f"AGENT_MISMATCH: proof sub '{agent_id}' != expected '{expected_agent_id}'")

    agent = registry.get(agent_id)
    if agent is None:
        raise ValueError(f"UNREGISTERED_AGENT: agent '{agent_id}' is not registered")

    # Verify signature with the agent's registered public key
    try:
        claims = jwt.decode(
            proof,
            agent.public_key,
            algorithms=["EdDSA"],
        )
    except jwt.InvalidSignatureError:
        raise ValueError("INVALID_PROOF_SIGNATURE: proof signature does not match registered key")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"INVALID_PROOF: {e}")

    # Check freshness
    iat = claims.get("iat", 0)
    if time.time() - iat > _PROOF_MAX_AGE:
        raise ValueError("PROOF_EXPIRED: proof is too old (max 30 seconds)")

    # Check action binding
    if claims.get("action") != expected_action:
        raise ValueError(f"PROOF_ACTION_MISMATCH: proof action '{claims.get('action')}' != '{expected_action}'")
    if claims.get("resource") != expected_resource:
        raise ValueError(f"PROOF_RESOURCE_MISMATCH: proof resource '{claims.get('resource')}' != '{expected_resource}'")

    # Check action_digest binding (MANDATORY when the gateway provides an expected digest)
    if expected_action_digest:
        proof_digest = claims.get("action_digest")
        if not proof_digest:
            raise ValueError(
                f"PROOF_DIGEST_MISSING: proof must include action_digest claim "
                f"(expected '{expected_action_digest}')"
            )
        if proof_digest != expected_action_digest:
            raise ValueError(
                f"PROOF_DIGEST_MISMATCH: proof action_digest '{proof_digest}' "
                f"!= computed '{expected_action_digest}'"
            )

    # Check JTI replay (distinct cache from token JTIs)
    jti = claims.get("jti", "")
    if jti in _proof_jti_cache:
        raise ValueError("PROOF_REPLAY: proof JTI has already been used")
    _proof_jti_cache[jti] = time.time() + _PROOF_MAX_AGE
    # Clean old entries
    now = time.time()
    expired = [k for k, v in _proof_jti_cache.items() if v < now]
    for k in expired:
        del _proof_jti_cache[k]

    return agent
