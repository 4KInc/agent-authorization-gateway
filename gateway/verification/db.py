"""Database resource verifier.

Verification strategy (in priority order):
1. reachability_url → HTTP GET probe (live)
2. provider=firestore + project_id → Firestore REST API (live, GCP ADC)
3. provider=cloudsql + project_id + instance → Cloud SQL Admin API (live, GCP ADC)
4. connection_string present → TCP connect to host:port (live, no auth needed)
5. engine or provider metadata present → "metadata_only"
6. Nothing → "skipped"
"""

from __future__ import annotations

from .base import ResourceVerifier, VerificationResult, register_verifier
from ._http import probe_url, probe_gcp_api, probe_tcp, parse_connection_string


class DatabaseVerifier(ResourceVerifier):

    @property
    def resource_type(self) -> str:
        return "db"

    @property
    def required_metadata_fields(self) -> list[str]:
        return []

    async def verify(self, reachability_url: str | None, metadata: dict | None) -> VerificationResult:
        meta = metadata or {}

        # 1. Explicit URL probe
        if reachability_url:
            return await probe_url(reachability_url, "database")

        provider = meta.get("provider", "")
        project_id = meta.get("project_id", "")
        engine = meta.get("engine", "")
        conn = meta.get("connection_string", "")

        # 2. Firestore: check project database metadata
        if provider == "firestore" and project_id:
            api_url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)"
            result = await probe_gcp_api(api_url, "Firestore database")
            result.details["provider"] = "firestore"
            result.details["project_id"] = project_id
            return result

        # 3. Cloud SQL: check instance metadata
        instance = meta.get("instance", "")
        if provider == "cloudsql" and project_id and instance:
            api_url = f"https://sqladmin.googleapis.com/v1/projects/{project_id}/instances/{instance}"
            result = await probe_gcp_api(api_url, "Cloud SQL instance")
            result.details["provider"] = "cloudsql"
            result.details["project_id"] = project_id
            result.details["instance"] = instance
            return result

        # 4. Connection string → TCP probe to host:port
        if conn:
            parsed = parse_connection_string(conn)
            if parsed:
                host, port = parsed
                result = await probe_tcp(host, port, f"{engine or 'database'} server")
                result.details["engine"] = engine
                result.details["provider"] = provider
                return result

        # 5. Metadata present but no live probe possible
        if engine or provider:
            return VerificationResult(
                status="metadata_only",
                reason=f"Database metadata recorded (engine={engine or 'unspecified'}). "
                       f"Provide a connection_string for TCP verification or a GCP provider for API verification.",
                details={"engine": engine, "provider": provider},
            )

        # 6. Nothing
        return VerificationResult(
            status="skipped",
            reason="No reachability_url or database metadata provided",
        )


register_verifier(DatabaseVerifier())
