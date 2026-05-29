"""Scoped authorization token issuance — Ed25519 (EdDSA, RFC 8037).

Issues 60-second JWTs signed with the Gateway's Ed25519 private key.
Tokens are single-use, tenant-scoped, and cryptographically bound to
the action they authorize via action_digest.

Resources verify tokens using only the Gateway's public key (fetched
from /keys). No shared secret — asymmetric verification only.
"""

from __future__ import annotations

import base64
import hashlib
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonicalize

DEFAULT_TTL_SECONDS = 60
TOKEN_ISSUER = "agent-authorization-gateway"
TOKEN_AUDIENCE = "protected-resource"
CLOCK_SKEW_SECONDS = 5


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
    private_key: Ed25519PrivateKey,
    agent_id: str,
    action: str,
    resource: str,
    action_digest: str,
    decision: str,
    receipt_hash: str,
    tenant: str = "default",
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    receipt_jti: str | None = None,
) -> tuple[str, str]:
    """Issue a scoped authorization token (JWT) signed with Ed25519.

    Returns (token_string, jti) so the jti can be embedded in the receipt.

    The token is bound to:
    - The specific action + resource (via action_digest)
    - The authorization decision (via receipt_hash)
    - A 60-second TTL
    - A unique jti (prevents replay)
    """
    now = time.time()
    jti = receipt_jti or str(uuid.uuid4())
    payload = {
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "sub": agent_id,
        "tid": tenant,
        "action": action,
        "resource": resource,
        "action_digest": action_digest,
        "decision": decision,
        "receipt_hash": receipt_hash,
        "jti": jti,
        "iat": int(now),
        "exp": int(now) + ttl_seconds,
    }

    # PyJWT supports Ed25519 via the "EdDSA" algorithm
    token = jwt.encode(payload, private_key, algorithm="EdDSA")
    return token, jti


def verify_token(
    token: str,
    public_key: Ed25519PublicKey,
    leeway: int = CLOCK_SKEW_SECONDS,
) -> dict:
    """Verify and decode a scoped authorization token.

    Uses the Gateway's Ed25519 public key for verification.
    No shared secret needed — the resource only needs the public key.

    Raises jwt.InvalidTokenError on any failure.
    """
    return jwt.decode(
        token,
        public_key,
        algorithms=["EdDSA"],
        issuer=TOKEN_ISSUER,
        audience=TOKEN_AUDIENCE,
        leeway=leeway,
    )


def public_key_from_jwk(jwk: dict) -> Ed25519PublicKey:
    """Reconstruct an Ed25519 public key from a JWK dict."""
    x = jwk["x"]
    x = x.replace("-", "+").replace("_", "/")
    padding = 4 - len(x) % 4
    if padding != 4:
        x += "=" * padding
    key_bytes = base64.b64decode(x)
    return Ed25519PublicKey.from_public_bytes(key_bytes)
