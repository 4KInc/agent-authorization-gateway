"""File storage / object store resource verifier.

Verification strategy (in priority order):
1. reachability_url → HTTP GET probe (live)
2. provider=gcs + bucket → GCS JSON API (live, GCP ADC, 403=exists)
3. provider=s3 + bucket + verification_credentials → AWS SigV4 HEAD (live)
4. provider=s3 + bucket (no creds) → unauthenticated HEAD (live, 403=exists)
5. provider=azure_blob + account + container + creds → Bearer HEAD (live)
6. bucket or provider metadata present → "metadata_only"
7. Nothing → "skipped"
"""

from __future__ import annotations

from .base import ResourceVerifier, VerificationResult, register_verifier
from ._http import (
    probe_url, probe_gcp_api, probe_aws_api,
    probe_with_bearer, probe_url_unauthenticated,
)


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

        # 2. GCS: authenticated metadata read (403=exists)
        if bucket and provider == "gcs":
            api_url = f"https://storage.googleapis.com/storage/v1/b/{bucket}"
            result = await probe_gcp_api(api_url, "GCS bucket", accept_statuses={200, 403})
            result.details["bucket"] = bucket
            result.details["provider"] = "gcs"
            return result

        # 3. S3 with caller-supplied AWS credentials
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

        # 4. S3 without credentials — unauthenticated HEAD (403=exists, 404=doesn't)
        if bucket and provider == "s3":
            s3_url = f"https://{bucket}.s3.amazonaws.com/"
            result = await probe_url_unauthenticated(s3_url, "S3 bucket")
            # S3 returns 403 for existing private buckets, 404 for nonexistent
            if result.status == "verified" and result.details.get("status_code") == 404:
                result.status = "failed"
                result.reason = f"S3 bucket '{bucket}' not found (returned 404)"
            else:
                result.details["bucket"] = bucket
                result.details["provider"] = "s3"
            return result

        # 5. Azure Blob with caller-supplied bearer token
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

        # 6. Azure Blob without creds — unauthenticated HEAD
        if bucket and provider == "azure_blob" and account:
            azure_url = f"https://{account}.blob.core.windows.net/{bucket}?restype=container"
            result = await probe_url_unauthenticated(azure_url, "Azure Blob container")
            if result.status == "verified" and result.details.get("status_code") == 404:
                result.status = "failed"
                result.reason = f"Azure container '{bucket}' not found in account '{account}'"
            else:
                result.details["container"] = bucket
                result.details["provider"] = "azure_blob"
                result.details["account"] = account
            return result

        # 7. Descriptive metadata only
        if bucket or provider:
            return VerificationResult(
                status="metadata_only",
                reason=f"Storage metadata recorded (provider={provider or 'unspecified'}, bucket={bucket or 'unspecified'}). No live probe performed.",
                details={"bucket": bucket, "provider": provider,
                         "prefix": meta.get("prefix", ""),
                         "content_classification": meta.get("content_classification", "")},
            )

        # 8. Nothing
        return VerificationResult(
            status="skipped",
            reason="No reachability_url or storage metadata provided",
        )


register_verifier(StorageVerifier())
