"""Agent identity verification — DPoP-style proof of possession.

Each Worker agent has a long-lived Ed25519 keypair (the agent's identity).
Before authorizing, the agent must prove it holds the private key by
signing a DPoP-style proof (RFC 9449 inspired).

Registration requires proof of possession: the registrant must sign a
challenge nonce with the private key corresponding to the public key
being registered. This prevents registering keys you don't control.

Flow:
1. Agent generates Ed25519 keypair
2. Agent requests a registration challenge (nonce)
3. Agent signs the challenge and registers with the signed proof
4. Every authorize_action call includes a signed DPoP proof JWT
5. Gateway verifies the proof before evaluating policy
6. Receipt includes the verified agent_id and the agent's key fingerprint
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

logger = logging.getLogger("gateway.identity")

_proof_jti_cache: dict[str, float] = {}
_PROOF_JTI_MAX = 5000
_PROOF_MAX_AGE = 30
_CHALLENGE_TTL = 60
_CHALLENGE_RATE_LIMIT = 10  # per minute per IP
_CHALLENGE_RATE_WINDOW = 60  # seconds
_CHALLENGE_DICT_MAX = 10_000


@dataclass
class RegisteredAgent:
    """A registered agent with a verified identity."""
    agent_id: str
    public_key: Ed25519PublicKey
    kid: str
    registered_at: float = field(default_factory=time.time)
    live_challenge_url: str | None = None


class AgentAlreadyRegistered(Exception):
    """Raised when trying to register an agent_id that already exists."""


def _parse_jwk(public_key_jwk: dict) -> tuple[Ed25519PublicKey, bytes, str]:
    """Parse and validate an Ed25519 JWK. Returns (public_key, raw_bytes, kid)."""
    if public_key_jwk.get("kty") != "OKP":
        raise ValueError(f"JWK kty must be 'OKP', got '{public_key_jwk.get('kty')}'")
    if public_key_jwk.get("crv") != "Ed25519":
        raise ValueError(f"JWK crv must be 'Ed25519', got '{public_key_jwk.get('crv')}'")
    x = public_key_jwk.get("x", "")
    if not x:
        raise ValueError("JWK missing 'x' field")
    x_padded = x.replace("-", "+").replace("_", "/")
    padding = 4 - len(x_padded) % 4
    if padding != 4:
        x_padded += "=" * padding
    key_bytes = base64.b64decode(x_padded)
    if len(key_bytes) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(key_bytes)}")
    public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
    kid = "agent-" + hashlib.sha256(key_bytes).hexdigest()[:16]
    return public_key, key_bytes, kid


def validate_agent_id(agent_id: str) -> None:
    """Validate agent_id format. Raises ValueError if invalid."""
    import re
    if not re.match(r"^[a-zA-Z0-9_-]{1,256}$", agent_id):
        raise ValueError(f"agent_id must match [a-zA-Z0-9_-]{{1,256}}, got '{agent_id[:64]}'")


class AgentRegistry:
    """Agent identity registry backed by in-memory cache + optional Firestore.

    In-memory dict is the hot path for DPoP verification. Firestore is the
    durable store that survives Cloud Run cold starts. Writes go to both;
    reads come from memory (populated from Firestore on startup via load_all).
    """

    def __init__(self, tenant: str = "default", firestore_db=None, **kwargs):
        self._agents: dict[str, RegisteredAgent] = {}
        self._by_kid: dict[str, RegisteredAgent] = {}
        self._db = firestore_db
        self._tenant = tenant

    def register(self, agent_id: str, public_key_jwk: dict, live_challenge_url: str | None = None, **kwargs) -> RegisteredAgent:
        """Register an agent's public key with replace semantics."""
        pub_key, key_bytes, kid = _parse_jwk(public_key_jwk)
        existing = self._agents.get(agent_id)
        if existing:
            self._by_kid.pop(existing.kid, None)
        agent = RegisteredAgent(
            agent_id=agent_id, public_key=pub_key, kid=kid,
            live_challenge_url=live_challenge_url,
        )
        self._agents[agent_id] = agent
        self._by_kid[kid] = agent
        logger.info("Registered agent: %s kid=%s", agent_id, kid)
        self._persist(agent, public_key_jwk)
        return agent

    def revoke(self, agent_id: str, **kwargs) -> None:
        agent = self._agents.pop(agent_id, None)
        if agent is None:
            raise ValueError(f"Agent '{agent_id}' is not registered")
        self._by_kid.pop(agent.kid, None)
        self._delete_persisted(agent_id)

    def get(self, agent_id: str) -> RegisteredAgent | None:
        return self._agents.get(agent_id)

    def get_by_kid(self, kid: str) -> RegisteredAgent | None:
        return self._by_kid.get(kid)

    def list_agents(self, **kwargs) -> list[dict]:
        return [
            {
                "agent_id": a.agent_id,
                "kid": a.kid,
                "registered_at": a.registered_at,
                "live_challenge_url": a.live_challenge_url,
            }
            for a in self._agents.values()
        ]

    # -- Firestore persistence -------------------------------------------------

    def _persist(self, agent: RegisteredAgent, public_key_jwk: dict | None = None) -> bool:
        """Persist a single agent record to Firestore. No-op without Firestore."""
        if self._db is None:
            return False
        try:
            jwk = public_key_jwk
            if jwk is None:
                pub_bytes = agent.public_key.public_bytes_raw()
                jwk = {
                    "kty": "OKP", "crv": "Ed25519",
                    "x": base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode(),
                }
            doc_ref = (
                self._db.collection("tenants").document(self._tenant)
                .collection("agent_registry").document(agent.agent_id)
            )
            doc_ref.set({
                "agent_id": agent.agent_id,
                "kid": agent.kid,
                "public_key_jwk": jwk,
                "registered_at": agent.registered_at,
                "live_challenge_url": agent.live_challenge_url,
                "status": "active",
            })
            return True
        except Exception as e:
            logger.warning("Failed to persist agent %s to Firestore: %s", agent.agent_id, e)
            return False

    def update_verification(self, agent_id: str, card_verification: str | None, card_reason: str | None,
                            live_verification: str | None, live_reason: str | None, card_url: str | None) -> None:
        """Persist verification results on the agent doc."""
        if self._db is None:
            return
        try:
            fields: dict = {}
            if card_verification:
                fields["agent_card_verification"] = card_verification
            if card_reason:
                fields["agent_card_verification_reason"] = card_reason
            if live_verification:
                fields["live_challenge_verification"] = live_verification
            if live_reason:
                fields["live_challenge_verification_reason"] = live_reason
            if card_url:
                fields["agent_card_url"] = card_url
            if fields:
                (self._db.collection("tenants").document(self._tenant)
                 .collection("agent_registry").document(agent_id).update(fields))
        except Exception as e:
            logger.warning("Failed to update verification for %s: %s", agent_id, e)

    def _delete_persisted(self, agent_id: str) -> bool:
        """Soft-delete an agent in Firestore (set status to revoked). No-op without Firestore."""
        if self._db is None:
            return False
        try:
            from datetime import datetime, timezone
            (
                self._db.collection("tenants").document(self._tenant)
                .collection("agent_registry").document(agent_id)
                .update({"status": "revoked", "revoked_at": datetime.now(timezone.utc).isoformat()})
            )
            return True
        except Exception as e:
            logger.warning("Failed to revoke agent %s in Firestore: %s", agent_id, e)
            return False

    def load_all(self) -> int:
        """Hydrate in-memory registry from Firestore on startup.

        Returns the number of agents loaded.
        """
        if self._db is None:
            return 0
        collection = (
            self._db.collection("tenants").document(self._tenant)
            .collection("agent_registry")
        )
        loaded = 0
        try:
            for doc in collection.stream():
                data = doc.to_dict()
                agent_id = data.get("agent_id") or doc.id
                jwk = data.get("public_key_jwk")
                if data.get("status") == "revoked":
                    continue
                if not jwk or not jwk.get("x"):
                    logger.warning("Skipping agent %s: missing public_key_jwk", agent_id)
                    continue
                try:
                    pub_key, _, kid = _parse_jwk(jwk)
                except ValueError as e:
                    logger.warning("Skipping agent %s: invalid JWK: %s", agent_id, e)
                    continue
                agent = RegisteredAgent(
                    agent_id=agent_id,
                    public_key=pub_key,
                    kid=data.get("kid", kid),
                    registered_at=data.get("registered_at", 0),
                    live_challenge_url=data.get("live_challenge_url"),
                )
                self._agents[agent_id] = agent
                self._by_kid[agent.kid] = agent
                loaded += 1
        except Exception as e:
            logger.error("Failed to load agent registry from Firestore: %s", e)
        if loaded:
            logger.info("Loaded %d agents from Firestore for tenant %s", loaded, self._tenant)
        return loaded


# ============================================================================
# Registration Proof of Possession (PoP) — Challenge-Response
# ============================================================================

@dataclass
class _Challenge:
    nonce: str
    challenge_id: str
    tenant: str
    agent_id: str
    expires_at: float
    consumed: bool = False


class RegistrationChallengeCache:
    """In-memory cache of registration challenges. Single-use, 60-second TTL."""

    def __init__(self, ttl_seconds: int = _CHALLENGE_TTL):
        self._ttl = ttl_seconds
        self._challenges: dict[str, _Challenge] = {}
        self._ip_requests: dict[str, list[float]] = {}

    def _key(self, tenant: str, agent_id: str, nonce: str) -> str:
        return f"{tenant}:{agent_id}:{nonce}"

    def check_rate_limit(self, client_ip: str) -> bool:
        """Returns True if request is within rate limit, False if it should be rejected."""
        now = time.time()
        history = self._ip_requests.get(client_ip, [])
        history = [t for t in history if now - t < _CHALLENGE_RATE_WINDOW]
        if len(history) >= _CHALLENGE_RATE_LIMIT:
            self._ip_requests[client_ip] = history
            return False
        history.append(now)
        self._ip_requests[client_ip] = history
        return True

    def check_capacity(self) -> bool:
        """Returns True if dict has room, False if at capacity."""
        return len(self._challenges) < _CHALLENGE_DICT_MAX

    def issue(self, tenant: str, agent_id: str) -> dict:
        self._gc()
        nonce = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        challenge_id = str(uuid.uuid4())
        expires_at = time.time() + self._ttl
        ch = _Challenge(
            nonce=nonce, challenge_id=challenge_id,
            tenant=tenant, agent_id=agent_id, expires_at=expires_at,
        )
        self._challenges[self._key(tenant, agent_id, nonce)] = ch
        return {
            "nonce": nonce,
            "challenge_id": challenge_id,
            "expires_at": datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat(),
        }

    def consume(self, tenant: str, agent_id: str, nonce: str, challenge_id: str) -> tuple[bool, str]:
        self._gc()
        key = self._key(tenant, agent_id, nonce)
        ch = self._challenges.get(key)
        if ch is None:
            return False, "CHALLENGE_NOT_FOUND"
        if ch.consumed:
            return False, "CHALLENGE_REPLAY"
        if time.time() > ch.expires_at:
            return False, "CHALLENGE_EXPIRED"
        if ch.challenge_id != challenge_id:
            return False, "CHALLENGE_ID_MISMATCH"
        ch.consumed = True
        del self._challenges[key]
        return True, ""

    def _gc(self):
        now = time.time()
        expired = [k for k, v in self._challenges.items() if now > v.expires_at]
        for k in expired:
            del self._challenges[k]


def build_registration_message(
    tenant_id: str, agent_id: str, public_key_jwk: dict,
    nonce: str, challenge_id: str, iat: int,
) -> bytes:
    """Build the canonical message for registration PoP signature."""
    from .canonical import canonicalize
    return canonicalize({
        "v": "1",
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "public_key": public_key_jwk,
        "nonce": nonce,
        "challenge_id": challenge_id,
        "iat": iat,
    })


def verify_registration_proof(
    public_key_jwk: dict,
    proof: dict,
    tenant_id: str,
    agent_id: str,
    challenge_cache: RegistrationChallengeCache,
) -> tuple[bool, str]:
    """Verify a registration proof of possession.
    Returns (valid, error_code). error_code is empty string on success.
    """
    if not proof:
        return False, "NO_PROOF"

    nonce = proof.get("nonce")
    challenge_id = proof.get("challenge_id")
    signature_b64 = proof.get("signature")
    iat = proof.get("iat")

    if not all([nonce, challenge_id, signature_b64, iat is not None]):
        return False, "INVALID_PROOF_FORMAT"

    try:
        iat_int = int(iat)
    except (TypeError, ValueError):
        return False, "INVALID_PROOF_FORMAT"
    if abs(time.time() - iat_int) > _CHALLENGE_TTL:
        return False, "PROOF_EXPIRED"

    valid, err = challenge_cache.consume(tenant_id, agent_id, nonce, challenge_id)
    if not valid:
        return False, err

    try:
        sig_padded = signature_b64.replace("-", "+").replace("_", "/")
        pad = 4 - len(sig_padded) % 4
        if pad != 4:
            sig_padded += "=" * pad
        sig_bytes = base64.b64decode(sig_padded)
    except Exception:
        return False, "SIGNATURE_DECODE_ERROR"

    try:
        pub_key, _, _ = _parse_jwk(public_key_jwk)
    except ValueError:
        return False, "INVALID_PROOF_FORMAT"

    message = build_registration_message(
        tenant_id, agent_id, public_key_jwk, nonce, challenge_id, iat_int,
    )
    try:
        pub_key.verify(sig_bytes, message)
    except Exception:
        return False, "INVALID_PROOF_SIGNATURE"

    return True, ""


# ============================================================================
# DPoP Agent Proof (authorize path — unchanged)
# ============================================================================

def create_agent_proof(
    private_key: Ed25519PrivateKey,
    agent_id: str,
    action: str,
    resource: str,
    action_digest: str | None = None,
    gateway_url: str = "agent-authorization-gateway",
) -> str:
    """Create a DPoP-style proof JWT signed by the agent's private key."""
    if action_digest is None:
        from .tokens import compute_action_digest
        action_digest = compute_action_digest(agent_id, action, resource)

    now = time.time()
    payload = {
        "sub": agent_id,
        "htm": "POST",
        "htu": gateway_url,
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

    try:
        header = jwt.get_unverified_header(proof)
        unverified = jwt.decode(proof, options={"verify_signature": False})
    except jwt.InvalidTokenError as e:
        raise ValueError(f"INVALID_PROOF: malformed proof JWT: {e}")

    agent_id = unverified.get("sub", "")
    if agent_id != expected_agent_id:
        raise ValueError(f"AGENT_MISMATCH: proof sub '{agent_id}' != expected '{expected_agent_id}'")

    agent = registry.get(agent_id)
    if agent is None:
        raise ValueError(f"UNREGISTERED_AGENT: agent '{agent_id}' is not registered")

    try:
        claims = jwt.decode(proof, agent.public_key, algorithms=["EdDSA"])
    except jwt.InvalidSignatureError:
        raise ValueError("INVALID_PROOF_SIGNATURE: proof signature does not match registered key")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"INVALID_PROOF: {e}")

    iat = claims.get("iat", 0)
    if time.time() - iat > _PROOF_MAX_AGE:
        raise ValueError("PROOF_EXPIRED: proof is too old (max 30 seconds)")

    if claims.get("action") != expected_action:
        raise ValueError(f"PROOF_ACTION_MISMATCH: proof action '{claims.get('action')}' != '{expected_action}'")
    if claims.get("resource") != expected_resource:
        raise ValueError(f"PROOF_RESOURCE_MISMATCH: proof resource '{claims.get('resource')}' != '{expected_resource}'")

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

    jti = claims.get("jti", "")
    if jti in _proof_jti_cache:
        raise ValueError("PROOF_REPLAY: proof JTI has already been used")
    _proof_jti_cache[jti] = time.time() + _PROOF_MAX_AGE
    now = time.time()
    expired = [k for k, v in _proof_jti_cache.items() if v < now]
    for k in expired:
        del _proof_jti_cache[k]

    return agent
