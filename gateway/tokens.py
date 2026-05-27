"""Scoped authorization token issuance.

Issues 60-second JWTs bound to a specific action digest.
Tokens are single-use, tenant-scoped, and cryptographically
bound to the action they authorize.
"""

from __future__ import annotations

import hashlib
import time
import uuid

import jwt

from .canonical import canonicalize

DEFAULT_TTL_SECONDS = 60
TOKEN_ISSUER = "agent-authorization-gateway"
TOKEN_AUDIENCE = "protected-resource"


def compute_action_digest(
    agent_id: str,
    action: str,
    resource: str,
    parameters: dict | None = None,
) -> str:
    """Compute a SHA-256 digest of the action intent for token binding."""
    intent_obj = {
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
    }
    if parameters:
        intent_obj["parameters"] = parameters
    body_bytes = canonicalize(intent_obj)
    return "sha256:" + hashlib.sha256(body_bytes).hexdigest()


def issue_token(
    secret: str,
    agent_id: str,
    action_digest: str,
    decision: str,
    receipt_hash: str,
    tenant: str = "default",
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> str:
    """Issue a scoped authorization token (JWT).

    The token is bound to:
    - The specific action (via action_digest)
    - The authorization decision (via receipt_hash)
    - A 60-second TTL
    - A unique jti (prevents replay)
    """
    now = time.time()
    payload = {
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "sub": agent_id,
        "tid": tenant,
        "action_digest": action_digest,
        "decision": decision,
        "receipt_hash": receipt_hash,
        "jti": str(uuid.uuid4()),
        "iat": int(now),
        "exp": int(now) + ttl_seconds,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def verify_token(token: str, secret: str) -> dict:
    """Verify and decode a scoped authorization token.

    Raises jwt.InvalidTokenError on any failure.
    """
    return jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        issuer=TOKEN_ISSUER,
        audience=TOKEN_AUDIENCE,
    )
