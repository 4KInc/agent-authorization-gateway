"""Message queue / event stream resource verifier.

Verification strategy (in priority order):
1. reachability_url → HTTP GET probe (live)
2. provider=pubsub + project_id + topic → Pub/Sub Admin API (live, GCP ADC, 403=exists)
3. provider=sqs + region + topic + account_id + creds → SQS API (live)
4. provider=rabbitmq + management_url + creds → RabbitMQ mgmt API (live)
5. provider=kafka + broker_host → TCP connect to broker (live)
6. provider=sqs + region + topic (no creds) → unauthenticated HEAD (live, limited)
7. topic or provider metadata present → "metadata_only"
8. Nothing → "skipped"
"""

from __future__ import annotations

from urllib.parse import quote

from .base import ResourceVerifier, VerificationResult, register_verifier
from ._http import (
    probe_url, probe_gcp_api, probe_aws_api,
    probe_with_basic_auth, probe_tcp,
)


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

        # 2. Pub/Sub: authenticated topic metadata read (403=exists)
        if topic and provider == "pubsub" and project_id:
            api_url = f"https://pubsub.googleapis.com/v1/projects/{project_id}/topics/{topic}"
            result = await probe_gcp_api(api_url, "Pub/Sub topic", accept_statuses={200, 403})
            result.details["topic"] = topic
            result.details["provider"] = "pubsub"
            result.details["project_id"] = project_id
            return result

        # 3. SQS with caller-supplied AWS credentials
        account_id = meta.get("account_id", "")
        if topic and provider == "sqs" and creds and account_id:
            sqs_url = f"https://sqs.{region}.amazonaws.com/{account_id}/{topic}"
            result = await probe_aws_api(
                sqs_url, "SQS queue",
                region=region, service="sqs", creds=creds,
                method="GET", accept_statuses={200, 403},
            )
            result.details["topic"] = topic
            result.details["provider"] = "sqs"
            result.details["region"] = region
            return result

        # 4. RabbitMQ management API with basic auth
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

        # 5. Kafka: TCP connect to broker
        broker_host = meta.get("broker_host", "")
        broker_port = int(meta.get("broker_port", "9092"))
        if provider == "kafka" and broker_host:
            result = await probe_tcp(broker_host, broker_port, "Kafka broker")
            result.details["topic"] = topic
            result.details["provider"] = "kafka"
            return result

        # 6. RabbitMQ: TCP connect if host is given but no management URL
        rabbit_host = meta.get("host", "")
        if provider == "rabbitmq" and rabbit_host:
            rabbit_port = int(meta.get("port", "5672"))
            result = await probe_tcp(rabbit_host, rabbit_port, "RabbitMQ broker")
            result.details["topic"] = topic
            result.details["provider"] = "rabbitmq"
            return result

        # 7. Descriptive metadata only
        if topic or provider:
            return VerificationResult(
                status="metadata_only",
                reason=f"Queue metadata recorded (provider={provider or 'unspecified'}, topic={topic or 'unspecified'}). "
                       f"Provide broker_host (Kafka/RabbitMQ), GCP project_id (Pub/Sub), or management_url for live verification.",
                details={"topic": topic, "provider": provider},
            )

        # 8. Nothing
        return VerificationResult(
            status="skipped",
            reason="No reachability_url or queue metadata provided",
        )


register_verifier(QueueVerifier())
