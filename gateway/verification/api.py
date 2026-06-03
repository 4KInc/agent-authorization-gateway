"""API endpoint resource verifier.

Verification strategy (in priority order):
1. reachability_url → HTTP HEAD probe (live, returns "verified" or "failed")
2. base_url, auth_type, or openapi_spec_url present → "metadata_only"
3. Nothing provided → "skipped"

For API resources, the only way to get "verified" is to provide a
reachability_url that the gateway can reach. base_url is descriptive
metadata — the gateway does not probe it because it may require auth
credentials the gateway does not hold.

Supported metadata fields:
- base_url: The API base URL (descriptive, not probed)
- auth_type: Authentication type (e.g., "bearer", "api_key", "oauth2", "iam")
- openapi_spec_url: URL to an OpenAPI spec for the API
- http_method: Expected HTTP method (descriptive)
"""

from __future__ import annotations

from .base import ResourceVerifier, VerificationResult, register_verifier
from ._http import probe_url


class ApiVerifier(ResourceVerifier):

    @property
    def resource_type(self) -> str:
        return "api"

    @property
    def required_metadata_fields(self) -> list[str]:
        return []

    async def verify(self, reachability_url: str | None, metadata: dict | None) -> VerificationResult:
        meta = metadata or {}

        # 1. Live probe via explicit reachability_url
        if reachability_url:
            return await probe_url(
                reachability_url, "API",
                method="HEAD",
                accept_statuses={200, 204, 301, 302, 405},
            )

        # 2. Descriptive metadata — no live probe
        base_url = meta.get("base_url", "")
        auth_type = meta.get("auth_type", "")
        spec_url = meta.get("openapi_spec_url", "")
        if base_url or auth_type or spec_url:
            return VerificationResult(
                status="metadata_only",
                reason=f"API metadata recorded (auth_type={auth_type or 'unspecified'}). No live probe performed.",
                details={"auth_type": auth_type, "has_base_url": bool(base_url),
                         "has_openapi_spec": bool(spec_url)},
            )

        # 3. Nothing
        return VerificationResult(
            status="skipped",
            reason="No reachability_url or API metadata provided",
        )


register_verifier(ApiVerifier())
