"""Function / compute resource verifier.

Verification strategy (in priority order):
1. reachability_url → HTTP HEAD probe (live)
2. provider=cloud_functions + project_id + region + function_name → GCP API (live)
3. provider=cloud_run_jobs + project_id + region + function_name → GCP API (live)
4. provider=lambda + region + function_name + verification_credentials → AWS API (live)
5. function_name or provider metadata present → "metadata_only"
6. Nothing → "skipped"

Supported metadata fields:
- function_name: The function or job name
- provider: Provider ("cloud_functions", "lambda", "cloud_run_jobs")
- project_id: GCP project ID (for GCP live probes)
- region: Deployment region (required for live probes)
- runtime: Runtime identifier (descriptive)

Verification credentials (ephemeral, never persisted):
- verification_credentials.aws_access_key_id
- verification_credentials.aws_secret_access_key
- verification_credentials.aws_session_token
"""

from __future__ import annotations

from .base import ResourceVerifier, VerificationResult, register_verifier
from ._http import probe_url, probe_gcp_api, probe_aws_api


class FunctionVerifier(ResourceVerifier):

    @property
    def resource_type(self) -> str:
        return "function"

    @property
    def required_metadata_fields(self) -> list[str]:
        return []

    async def verify(self, reachability_url: str | None, metadata: dict | None) -> VerificationResult:
        meta = metadata or {}
        creds = meta.get("verification_credentials", {})

        # 1. Explicit URL probe (HTTPS-triggered functions)
        if reachability_url:
            return await probe_url(
                reachability_url, "function",
                method="HEAD",
                accept_statuses={200, 204, 401, 403, 405},
            )

        function_name = meta.get("function_name", "")
        provider = meta.get("provider", "")
        project_id = meta.get("project_id", "")
        region = meta.get("region", "")

        # 2. Cloud Functions v2: authenticated metadata read
        if provider == "cloud_functions" and project_id and region and function_name:
            api_url = (
                f"https://cloudfunctions.googleapis.com/v2/"
                f"projects/{project_id}/locations/{region}/functions/{function_name}"
            )
            result = await probe_gcp_api(api_url, "Cloud Function", accept_statuses={200, 403})
            result.details["function_name"] = function_name
            result.details["provider"] = "cloud_functions"
            result.details["region"] = region
            return result

        # 3. Cloud Run Jobs: authenticated metadata read
        if provider == "cloud_run_jobs" and project_id and region and function_name:
            api_url = (
                f"https://run.googleapis.com/v2/"
                f"projects/{project_id}/locations/{region}/jobs/{function_name}"
            )
            result = await probe_gcp_api(api_url, "Cloud Run Job", accept_statuses={200, 403})
            result.details["function_name"] = function_name
            result.details["provider"] = "cloud_run_jobs"
            result.details["region"] = region
            return result

        # 4. AWS Lambda: GetFunction with caller-supplied credentials
        if provider == "lambda" and region and function_name and creds:
            lambda_url = (
                f"https://lambda.{region}.amazonaws.com"
                f"/2015-03-31/functions/{function_name}"
            )
            result = await probe_aws_api(
                lambda_url, "Lambda function",
                region=region, service="lambda", creds=creds,
            )
            result.details["function_name"] = function_name
            result.details["provider"] = "lambda"
            result.details["region"] = region
            return result

        # 5. Descriptive metadata — no live probe
        if function_name or provider:
            return VerificationResult(
                status="metadata_only",
                reason=f"Function metadata recorded (provider={provider or 'unspecified'}, name={function_name or 'unspecified'}). No live probe performed.",
                details={
                    "function_name": function_name,
                    "provider": provider,
                    "region": region,
                    "runtime": meta.get("runtime", ""),
                },
            )

        # 6. Nothing
        return VerificationResult(
            status="skipped",
            reason="No reachability_url or function metadata provided",
        )


register_verifier(FunctionVerifier())
