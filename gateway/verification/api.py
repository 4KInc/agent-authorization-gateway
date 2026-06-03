"""API endpoint resource verifier.

Verification strategy (in priority order):
1. reachability_url → HTTP HEAD probe with GCP identity token (live)
2. base_url present → HTTP HEAD unauthenticated probe (live)
   Any response (including 401, 403) proves the endpoint exists.
3. auth_type or openapi_spec_url present → "metadata_only"
4. Nothing → "skipped"
"""

from __future__ import annotations

from .base import ResourceVerifier, VerificationResult, register_verifier
from ._http import probe_url, probe_url_unauthenticated


class ApiVerifier(ResourceVerifier):

    @property
    def resource_type(self) -> str:
        return "api"

    @property
    def required_metadata_fields(self) -> list[str]:
        return []

    async def verify(self, reachability_url: str | None, metadata: dict | None) -> VerificationResult:
        meta = metadata or {}

        # 1. Live probe via explicit reachability_url (with GCP identity token)
        if reachability_url:
            return await probe_url(
                reachability_url, "API",
                method="HEAD",
                accept_statuses={200, 204, 301, 302, 401, 403, 405},
            )

        # 2. Probe base_url unauthenticated — any response proves it exists
        base_url = meta.get("base_url", "")
        if base_url:
            result = await probe_url_unauthenticated(base_url, "API endpoint")
            result.details["auth_type"] = meta.get("auth_type", "")
            return result

        # 3. Descriptive metadata only
        auth_type = meta.get("auth_type", "")
        spec_url = meta.get("openapi_spec_url", "")
        if auth_type or spec_url:
            return VerificationResult(
                status="metadata_only",
                reason=f"API metadata recorded (auth_type={auth_type or 'unspecified'}). "
                       f"Provide a base_url for live verification.",
                details={"auth_type": auth_type, "has_openapi_spec": bool(spec_url)},
            )

        # 4. Nothing
        return VerificationResult(
            status="skipped",
            reason="No reachability_url or API metadata provided",
        )


register_verifier(ApiVerifier())
