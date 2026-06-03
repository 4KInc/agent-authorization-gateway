"""Database resource verifier.

Verification strategy (in priority order):
1. reachability_url → HTTP GET probe (live, returns "verified" or "failed")
2. provider=firestore + project_id → Firestore REST API metadata read (live)
3. provider=cloudsql + project_id + instance → Cloud SQL Admin API (live)
4. engine or connection_string metadata present → "metadata_only" (no live probe)
5. Nothing provided → "skipped"

Supported metadata fields:
- engine: Database engine (e.g., "postgresql", "mysql", "firestore", "bigquery")
- connection_string: Connection URL (recorded but never used for live connection)
- provider: Cloud provider (e.g., "firestore", "cloudsql", "alloydb")
- project_id: GCP project ID (enables live verification for GCP databases)
- instance: Cloud SQL instance name
"""

from __future__ import annotations

from .base import ResourceVerifier, VerificationResult, register_verifier
from ._http import probe_url, probe_gcp_api


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
            if result.status == "verified":
                result.details["provider"] = "firestore"
                result.details["project_id"] = project_id
            return result

        # 3. Cloud SQL: check instance metadata
        instance = meta.get("instance", "")
        if provider == "cloudsql" and project_id and instance:
            api_url = f"https://sqladmin.googleapis.com/v1/projects/{project_id}/instances/{instance}"
            result = await probe_gcp_api(api_url, "Cloud SQL instance")
            if result.status == "verified":
                result.details["provider"] = "cloudsql"
                result.details["project_id"] = project_id
                result.details["instance"] = instance
            return result

        # 4. Metadata present but no live probe possible
        if engine or conn or provider:
            return VerificationResult(
                status="metadata_only",
                reason=f"Database metadata recorded (engine={engine or 'unspecified'}). No live probe performed.",
                details={"engine": engine, "provider": provider,
                         "has_connection_string": bool(conn)},
            )

        # 5. Nothing provided
        return VerificationResult(
            status="skipped",
            reason="No reachability_url or database metadata provided",
        )


register_verifier(DatabaseVerifier())
