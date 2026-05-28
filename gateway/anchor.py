"""Merkle root anchor sinks — write-once tamper-evidence anchoring.

Anchor sinks persist Merkle roots to locations the Gateway operator
cannot retroactively rewrite without leaving evidence. This is the
final layer of tamper-evidence: even if Firestore is compromised,
the anchor proves the chain state at each checkpoint.

Two implementations:
- LocalAnchorSink: append-only signed log file (demo/dev fallback)
- CloudStorageAnchorSink: GCS bucket with object versioning + Cloud Logging
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonicalize

logger = logging.getLogger("gateway.anchor")


class AnchorRecord:
    """A single anchor checkpoint."""

    def __init__(
        self,
        merkle_root: str,
        receipt_count: int,
        tenant: str,
        timestamp: str | None = None,
        prev_anchor_hash: str | None = None,
    ):
        self.merkle_root = merkle_root
        self.receipt_count = receipt_count
        self.tenant = tenant
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.prev_anchor_hash = prev_anchor_hash or ("sha256:" + "0" * 64)

    def to_dict(self) -> dict:
        return {
            "merkle_root": self.merkle_root,
            "receipt_count": self.receipt_count,
            "tenant": self.tenant,
            "timestamp": self.timestamp,
            "prev_anchor_hash": self.prev_anchor_hash,
        }

    def compute_hash(self) -> str:
        body_bytes = canonicalize(self.to_dict())
        return "sha256:" + hashlib.sha256(body_bytes).hexdigest()


class AnchorSink(ABC):
    """Abstract anchor sink interface."""

    @abstractmethod
    async def anchor(self, record: AnchorRecord, private_key: Ed25519PrivateKey) -> dict:
        """Persist an anchor record. Returns metadata about the anchor."""
        ...

    @abstractmethod
    async def get_anchors(self, tenant: str) -> list[dict]:
        """Retrieve all anchors for a tenant."""
        ...


class LocalAnchorSink(AnchorSink):
    """Append-only signed log file anchor sink.

    Each anchor entry is signed with the Gateway's Ed25519 key and
    appended to a JSONL file. The file forms its own hash chain
    (each entry's prev_anchor_hash references the previous entry).
    """

    def __init__(self, log_dir: str | None = None):
        self._log_dir = Path(log_dir or os.environ.get("ANCHOR_LOG_DIR", "/tmp/gateway-anchors"))
        self._log_dir.mkdir(parents=True, exist_ok=True)

    def _log_path(self, tenant: str) -> Path:
        return self._log_dir / f"{tenant}-anchors.jsonl"

    async def anchor(self, record: AnchorRecord, private_key: Ed25519PrivateKey) -> dict:
        # Read last anchor hash for chain linkage
        log_path = self._log_path(record.tenant)
        prev_hash = "sha256:" + "0" * 64
        if log_path.exists():
            lines = log_path.read_text().strip().split("\n")
            if lines and lines[-1]:
                last = json.loads(lines[-1])
                prev_hash = last.get("anchor_hash", prev_hash)

        record.prev_anchor_hash = prev_hash
        anchor_hash = record.compute_hash()

        # Sign the anchor
        body_bytes = canonicalize(record.to_dict())
        sig_bytes = private_key.sign(body_bytes)
        sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()

        entry = {
            **record.to_dict(),
            "anchor_hash": anchor_hash,
            "sig": sig_b64,
        }

        # Append to log (append-only)
        with open(log_path, "a") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")

        logger.info(f"Anchored merkle_root={record.merkle_root[:24]}... count={record.receipt_count} to {log_path}")
        return {"sink": "local", "path": str(log_path), "anchor_hash": anchor_hash}

    async def get_anchors(self, tenant: str) -> list[dict]:
        log_path = self._log_path(tenant)
        if not log_path.exists():
            return []
        lines = log_path.read_text().strip().split("\n")
        return [json.loads(line) for line in lines if line]


class CloudStorageAnchorSink(AnchorSink):
    """Google Cloud Storage anchor sink with object versioning.

    Writes each anchor as a versioned object in a GCS bucket.
    Object versioning ensures previous anchors cannot be deleted
    without leaving evidence in the bucket's version history.

    Also writes a Cloud Logging entry for external observability.
    """

    def __init__(self, bucket_name: str | None = None, project_id: str | None = None):
        self._bucket_name = bucket_name or os.environ.get("ANCHOR_GCS_BUCKET", "")
        self._project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT", "")

    async def anchor(self, record: AnchorRecord, private_key: Ed25519PrivateKey) -> dict:
        anchor_hash = record.compute_hash()

        body_bytes = canonicalize(record.to_dict())
        sig_bytes = private_key.sign(body_bytes)
        sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()

        entry = {
            **record.to_dict(),
            "anchor_hash": anchor_hash,
            "sig": sig_b64,
        }

        # Write to GCS
        if self._bucket_name:
            try:
                from google.cloud import storage
                client = storage.Client(project=self._project_id)
                bucket = client.bucket(self._bucket_name)
                blob_name = f"anchors/{record.tenant}/{int(time.time())}-{anchor_hash[:16]}.json"
                blob = bucket.blob(blob_name)
                blob.upload_from_string(json.dumps(entry, indent=2), content_type="application/json")
                logger.info(f"Anchored to gs://{self._bucket_name}/{blob_name}")
            except Exception as e:
                logger.warning(f"GCS anchor failed (falling back to log): {e}")

        # Always log to Cloud Logging / stdout
        logger.info(f"ANCHOR: {json.dumps(entry, separators=(',', ':'))}")

        return {"sink": "gcs", "bucket": self._bucket_name, "anchor_hash": anchor_hash}

    async def get_anchors(self, tenant: str) -> list[dict]:
        if not self._bucket_name:
            return []
        try:
            from google.cloud import storage
            client = storage.Client(project=self._project_id)
            bucket = client.bucket(self._bucket_name)
            blobs = bucket.list_blobs(prefix=f"anchors/{tenant}/")
            anchors = []
            for blob in blobs:
                data = json.loads(blob.download_as_text())
                anchors.append(data)
            return anchors
        except Exception as e:
            logger.warning(f"Failed to list GCS anchors: {e}")
            return []


def create_anchor_sink() -> AnchorSink:
    """Create the appropriate anchor sink based on environment."""
    bucket = os.environ.get("ANCHOR_GCS_BUCKET", "")
    if bucket:
        logger.info(f"Using CloudStorage anchor sink: {bucket}")
        return CloudStorageAnchorSink(bucket_name=bucket)
    logger.info("Using local file anchor sink")
    return LocalAnchorSink()
