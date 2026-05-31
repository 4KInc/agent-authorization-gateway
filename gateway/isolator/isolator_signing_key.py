"""Loads the Isolator's own Ed25519 signing key from Secret Manager."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@dataclass
class IsolatorKey:
    kid: str
    private_key: Ed25519PrivateKey
    public_key_bytes: bytes

    def sign(self, payload: bytes) -> bytes:
        return self.private_key.sign(payload)

    def public_key_b64url(self) -> str:
        return base64.urlsafe_b64encode(self.public_key_bytes).decode().rstrip("=")


_cached: IsolatorKey | None = None


def load() -> IsolatorKey:
    global _cached
    if _cached is not None:
        return _cached

    local = os.environ.get("ISOLATOR_LOCAL_SIGNING_KEY", "")
    if local:
        data = json.loads(local)
    else:
        from google.cloud import secretmanager
        project_id = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{project_id}/secrets/gateway-isolator-signing-key/versions/latest"
        resp = client.access_secret_version(request={"name": name})
        data = json.loads(resp.payload.data.decode())

    priv_bytes = base64.b64decode(data["private_key"])
    pub_bytes = base64.b64decode(data["public_key"])
    priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)

    _cached = IsolatorKey(kid=data["kid"], private_key=priv, public_key_bytes=pub_bytes)
    return _cached
