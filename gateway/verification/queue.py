"""Message queue / event stream resource verifier.

Verification strategy (in priority order):
1. reachability_url → HTTP GET probe (live)
2. provider=pubsub + project_id + topic → Pub/Sub Admin API (live, GCP ADC)
3. provider=sqs + region + topic + verification_credentials → SQS GetQueueUrl (live)
4. provider=rabbitmq + verification_credentials + management_url → RabbitMQ mgmt API (live)
5. topic or provider metadata present → "metadata_only"
6. Nothing → "skipped"

Supported metadata fields:
- topic: Topic or queue name
- provider: Provider ("pubsub", "kafka", "sqs", "rabbitmq", "eventbridge")
- project_id: GCP project ID (for Pub/Sub)
- region: AWS region (for SQS)
- account_id: AWS account ID (for SQS queue URL construction)
- management_url: RabbitMQ management API base URL
- vhost: RabbitMQ virtual host (default: "/")
- subscription: Optional subscription name

Verification credentials (ephemeral, never persisted):
- verification_credentials.aws_access_key_id
- verification_credentials.aws_secret_access_key
- verification_credentials.aws_session_token
- verification_credentials.username (RabbitMQ)
- verification_credentials.password (RabbitMQ)
"""

from __future__ import annotations

from urllib.parse import quote

from .base import ResourceVerifier, VerificationResult, register_verifier
from ._http import probe_url, probe_gcp_api, probe_aws_api, probe_with_basic_auth


class QueueVerifier(ResourceVerifier):

    @property
    def resource_type(self) -> str:
        return "queue"

    @property
    def required_metadata_fields(self) -> list[str]:
        return []

    async def verify(self, reachability_url: str | None, metadata: dict | None) -> VerificationResult:
        meta = metadata or {}
        creds = meta.get("verification_credentials", {})

        # 1. Explicit URL probe
        if reachability_url:
            return await probe_url(reachability_url, "queue")

        topic = meta.get("topic", "")
        provider = meta.get("provider", "")
        project_id = meta.get("project_id", "")
        region = meta.get("region", "us-east-1")

        # 2. Pub/Sub: authenticated topic metadata read (GCP ADC)
        #    403 = topic exists but SA lacks pubsub.topics.get (still proves existence)
        if topic and provider == "pubsub" and project_id:
            api_url = f"https://pubsub.googleapis.com/v1/projects/{project_id}/topics/{topic}"
            result = await probe_gcp_api(api_url, "Pub/Sub topic", accept_statuses={200, 403})
            result.details["topic"] = topic
            result.details["provider"] = "pubsub"
            result.details["project_id"] = project_id
            return result

        # 3. SQS: GetQueueUrl with caller-supplied AWS credentials
        account_id = meta.get("account_id", "")
        if topic and provider == "sqs" and creds and account_id:
            sqs_url = (
                f"https://sqs.{region}.amazonaws.com/{account_id}/{topic}"
            )
            result = await probe_aws_api(
                sqs_url, "SQS queue",
                region=region, service="sqs", creds=creds,
                method="GET", accept_statuses={200, 403},
            )
            result.details["topic"] = topic
            result.details["provider"] = "sqs"
            result.details["region"] = region
            return result

        # 4. RabbitMQ: management API with basic auth
        management_url = meta.get("management_url", "")
        vhost = meta.get("vhost", "/")
        if topic and provider == "rabbitmq" and management_url and creds.get("username"):
            encoded_vhost = quote(vhost, safe="")
            encoded_queue = quote(topic, safe="")
            rabbit_url = f"{management_url.rstrip('/')}/api/queues/{encoded_vhost}/{encoded_queue}"
            result = await probe_with_basic_auth(
                rabbit_url, "RabbitMQ queue",
                username=creds["username"],
                password=creds.get("password", ""),
            )
            result.details["topic"] = topic
            result.details["provider"] = "rabbitmq"
            result.details["vhost"] = vhost
            return result

        # 5. Descriptive metadata — no live probe
        if topic or provider:
            return VerificationResult(
                status="metadata_only",
                reason=f"Queue metadata recorded (provider={provider or 'unspecified'}, topic={topic or 'unspecified'}). No live probe performed.",
                details={"topic": topic, "provider": provider},
            )

        # 6. Nothing
        return VerificationResult(
            status="skipped",
            reason="No reachability_url or queue metadata provided",
        )


register_verifier(QueueVerifier())
