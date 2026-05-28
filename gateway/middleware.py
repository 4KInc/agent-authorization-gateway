"""Resource-side token verification middleware.

FastAPI dependency that enforces Gateway authorization tokens on
protected endpoints. Resources use this to verify that every incoming
request carries a valid, non-expired, non-replayed Ed25519-signed token
bound to the correct action and resource.

Usage:
    from gateway.middleware import require_gateway_token

    @app.get("/customers/{id}")
    async def get_customer(id: str, claims=Depends(require_gateway_token("read_customer", "customers"))):
        ...
"""

from __future__ import annotations

import logging
import time
from functools import lru_cache
from typing import Any

import httpx
import jwt
from fastapi import HTTPException, Request

from .tokens import CLOCK_SKEW_SECONDS, TOKEN_AUDIENCE, TOKEN_ISSUER, public_key_from_jwk

logger = logging.getLogger("gateway.middleware")

# JTI replay cache: jti -> expiry timestamp
_jti_cache: dict[str, float] = {}
_JTI_CACHE_MAX = 10000

# JWK cache
_jwk_cache: dict[str, Any] = {}
_jwk_cache_ts: float = 0
_JWK_CACHE_TTL = 300  # 5 minutes


class TokenError(HTTPException):
    def __init__(self, code: str, detail: str):
        super().__init__(status_code=401, detail={"error": code, "message": detail})


def _clean_jti_cache():
    """Remove expired JTIs from the replay cache."""
    now = time.time()
    expired = [jti for jti, exp in _jti_cache.items() if exp < now]
    for jti in expired:
        del _jti_cache[jti]


async def _fetch_gateway_jwk(gateway_url: str) -> dict:
    """Fetch the Gateway's public key, with TTL caching."""
    global _jwk_cache, _jwk_cache_ts
    now = time.time()
    if _jwk_cache and (now - _jwk_cache_ts) < _JWK_CACHE_TTL:
        return _jwk_cache

    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{gateway_url}/keys", timeout=10)
        resp.raise_for_status()
        data = resp.json()

    _jwk_cache = data
    _jwk_cache_ts = now
    return data


def require_gateway_token(action: str, resource_pattern: str, gateway_url: str | None = None):
    """FastAPI dependency that validates a Gateway authorization token.

    Args:
        action: Expected action (e.g., "read_customer")
        resource_pattern: Expected resource pattern (e.g., "customers")
        gateway_url: Gateway base URL for fetching public keys.
                     Defaults to GATEWAY_URL env var or http://localhost:8080.
    """
    import os
    gw_url = gateway_url or os.environ.get("GATEWAY_URL", "http://localhost:8080")

    async def verify(request: Request) -> dict:
        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise TokenError("NO_TOKEN", "Missing Authorization: Bearer <token> header")

        token = auth_header[7:]

        # Fetch Gateway's public key
        try:
            key_data = await _fetch_gateway_jwk(gw_url)
            keys = key_data.get("keys", [])
            if not keys:
                raise TokenError("NO_KEY", "Gateway returned no public keys")
        except httpx.HTTPError as e:
            raise TokenError("KEY_FETCH_FAILED", f"Failed to fetch Gateway public key: {e}")

        # Try each key (supports key rotation)
        claims = None
        last_error = None
        for jwk in keys:
            try:
                pub_key = public_key_from_jwk(jwk)
                claims = jwt.decode(
                    token,
                    pub_key,
                    algorithms=["EdDSA"],
                    issuer=TOKEN_ISSUER,
                    audience=TOKEN_AUDIENCE,
                    leeway=CLOCK_SKEW_SECONDS,
                )
                break
            except jwt.ExpiredSignatureError:
                raise TokenError("EXPIRED", "Token has expired")
            except jwt.InvalidSignatureError:
                last_error = "INVALID_SIGNATURE"
                continue
            except jwt.InvalidTokenError as e:
                last_error = str(e)
                continue

        if claims is None:
            raise TokenError("INVALID_SIGNATURE", f"Token signature verification failed: {last_error}")

        # Check JTI replay
        jti = claims.get("jti")
        if jti:
            _clean_jti_cache()
            if jti in _jti_cache:
                raise TokenError("REPLAY", "Token has already been used (JTI replay)")
            _jti_cache[jti] = claims.get("exp", time.time() + 60) + CLOCK_SKEW_SECONDS
            if len(_jti_cache) > _JTI_CACHE_MAX:
                _clean_jti_cache()

        # Validate action
        token_action = claims.get("action", "")
        if token_action != action:
            raise TokenError("WRONG_ACTION", f"Token action '{token_action}' does not match required '{action}'")

        # Validate resource pattern
        token_resource = claims.get("resource", "")
        if resource_pattern not in token_resource and token_resource not in resource_pattern:
            raise TokenError("WRONG_RESOURCE", f"Token resource '{token_resource}' does not match '{resource_pattern}'")

        return claims

    return verify
