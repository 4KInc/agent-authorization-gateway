"""File storage / object store resource verifier.

Verification strategy (in priority order):
1. reachability_url → HTTP GET probe (live)
2. provider=gcs + bucket → GCS JSON API authenticated metadata read (live)
3. provider=s3 + bucket + region + verification_credentials → AWS S3 HEAD bucket (live)
4. provider=azure_blob + account + container + verification_credentials → Azure HEAD (live)
5. bucket or provider metadata present → "metadata_only"
6. Nothing → "skipped"

Supported metadata fields:
- bucket: Bucket or container name
- prefix: Object key prefix (path scope)
- provider: Cloud provider ("gcs", "s3", "azure_blob")
- project_id: GCP project ID (for GCS)
- region: AWS region (for S3, e.g., "us-east-1")
- account: Azure storage account name (for azure_blob)
- content_classification: Data classification ("pii", "phi", "public")

Verification credentials (ephemeral, never persisted):
- verification_credentials.aws_access_key_id
- verification_credentials.aws_secret_access_key
- verification_credentials.aws_session_token (optional, for temporary creds)
- verification_credentials.bearer_token (for Azure or custom endpoints)
"""

from __future__ import annotations

from .base import ResourceVerifier, VerificationResult, register_verifier
from ._http import probe_url, probe_gcp_api, probe_aws_api, probe_with_bearer


class StorageVerifier(ResourceVerifier):

    @property
    def resource_type(self) -> str:
        return "storage"

    @property
    def required_metadata_fields(self) -> list[str]:
        return []

    async def verify(self, reachability_url: str | None, metadata: dict | None) -> VerificationResult:
        meta = metadata or {}
        creds = meta.get("verification_credentials", {})

        # 1. Explicit URL probe
        if reachability_url:
            return await probe_url(reachability_url, "storage")

        bucket = meta.get("bucket", "")
        provider = meta.get("provider", "")

        # 2. GCS: authenticated metadata read via Google APIs
        #    403 = bucket exists but SA lacks storage.buckets.get (still proves existence)
        if bucket and provider == "gcs":
            api_url = f"https://storage.googleapis.com/storage/v1/b/{bucket}"
            result = await probe_gcp_api(api_url, "GCS bucket", accept_statuses={200, 403})
            result.details["bucket"] = bucket
            result.details["provider"] = "gcs"
            return result

        # 3. S3: HEAD bucket with caller-supplied AWS credentials
        region = meta.get("region", "us-east-1")
        if bucket and provider == "s3" and creds:
            s3_url = f"https://{bucket}.s3.{region}.amazonaws.com/"
            result = await probe_aws_api(
                s3_url, "S3 bucket",
                region=region, service="s3", creds=creds,
                method="HEAD", accept_statuses={200, 301, 403},
            )
            result.details["bucket"] = bucket
            result.details["provider"] = "s3"
            result.details["region"] = region
            return result

        # 4. Azure Blob: HEAD container with caller-supplied bearer token
        account = meta.get("account", "")
        if bucket and provider == "azure_blob" and account and creds.get("bearer_token"):
            azure_url = f"https://{account}.blob.core.windows.net/{bucket}?restype=container"
            result = await probe_with_bearer(
                azure_url, "Azure Blob container",
                token=creds["bearer_token"],
                method="HEAD", accept_statuses={200, 403},
            )
            result.details["container"] = bucket
            result.details["provider"] = "azure_blob"
            result.details["account"] = account
            return result

        # 5. Descriptive metadata — no live probe
        if bucket or provider:
            return VerificationResult(
                status="metadata_only",
                reason=f"Storage metadata recorded (provider={provider or 'unspecified'}, bucket={bucket or 'unspecified'}). No live probe performed.",
                details={"bucket": bucket, "provider": provider,
                         "prefix": meta.get("prefix", ""),
                         "content_classification": meta.get("content_classification", "")},
            )

        # 6. Nothing
        return VerificationResult(
            status="skipped",
            reason="No reachability_url or storage metadata provided",
        )


register_verifier(StorageVerifier())
