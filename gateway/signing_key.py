"""Shared signing key — loaded once from GCP Secret Manager.

All gateway surfaces (REST, MCP, ADK) use this SINGLE Ed25519 keypair.
No per-instance key generation. No per-service key publishing.

Secret Manager secret: gateway-signing-key
Format: {"kid": "gateway-hackathon-demo-XXXX", "private_pem": "-----BEGIN..."}

Local dev override: set GATEWAY_LOCAL_SIGNING_KEY env var to the JSON payload
(same format). For tests only — never used in deployed services.
"""

from __future__ import annotations

import base64
import json
import logging
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

logger = logging.getLogger("gateway.signing_key")

_cached_kid: str | None = None
_cached_key: Ed25519PrivateKey | None = None


def load_signing_key() -> tuple[str, Ed25519PrivateKey]:
    """Load the shared signing key from Secret Manager (or local override).

    Returns (kid, private_key). Caches in-process after first load.
    Raises RuntimeError if the key cannot be loaded — NO fallback to
    ephemeral key generation.
    """
    global _cached_kid, _cached_key
    if _cached_kid and _cached_key:
        return _cached_kid, _cached_key

    # Local dev override
    local_json = os.environ.get("GATEWAY_LOCAL_SIGNING_KEY", "")
    if local_json:
        logger.info("Loading signing key from GATEWAY_LOCAL_SIGNING_KEY env var (local dev)")
        payload = json.loads(local_json)
        kid = payload["kid"]
        pem = payload["private_pem"].encode()
        key = load_pem_private_key(pem, password=None)
        _cached_kid, _cached_key = kid, key
        return kid, key

    # Production: GCP Secret Manager
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
    secret_name = os.environ.get("GATEWAY_SIGNING_KEY_SECRET", "gateway-signing-key")

    if not project_id:
        raise RuntimeError(
            "Cannot load signing key: GOOGLE_CLOUD_PROJECT not set and "
            "GATEWAY_LOCAL_SIGNING_KEY not provided. No fallback — the gateway "
            "requires a configured signing key."
        )

    try:
        from google.cloud import secretmanager
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
        response = client.access_secret_version(request={"name": name})
        payload = json.loads(response.payload.data.decode("utf-8"))
    except Exception as e:
        raise RuntimeError(
            f"Failed to load signing key from Secret Manager "
            f"(project={project_id}, secret={secret_name}): {e}"
        ) from e

    kid = payload["kid"]
    pem = payload["private_pem"].encode()
    key = load_pem_private_key(pem, password=None)

    logger.info(f"Loaded shared signing key from Secret Manager: kid={kid}")
    _cached_kid, _cached_key = kid, key
    return kid, key


def get_public_jwk() -> dict:
    """Return the public JWK for the shared signing key."""
    kid, key = load_signing_key()
    pub_bytes = key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode("ascii")
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
        "x": x,
    }
