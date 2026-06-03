"""Unified artifact log — chronologically ordered hashes of all signed artifacts.

Every signed artifact in the system (receipts, audit reports, policy proposals,
incident reports, isolation records) gets an entry in this log. The log is the
input to the unified Merkle tree that gets anchored to Base L2.

This closes the verification gap: previously only receipts were anchored.
Now all agent artifacts are covered by the same tamper-evidence guarantee.

Storage: tenants/{tenant}/artifact_log/{seq_id} in Firestore
Fallback: in-memory list for tests
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger("gateway.artifact_log")


@dataclass
class ArtifactEntry:
    """One entry in the unified artifact log."""

    seq: int                    # monotonic sequence number in the log
    artifact_type: str          # "receipt", "audit_report", "policy_proposal",
                                # "incident_report", "isolation_record"
    artifact_id: str            # the artifact's own ID (receipt_hash, audit_id, etc.)
    artifact_hash: str          # sha256 of the JCS-canonicalized body
    agent_kid: str              # kid of the signing agent
    tenant: str
    created_at: str             # ISO 8601

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "artifact_type": self.artifact_type,
            "artifact_id": self.artifact_id,
            "artifact_hash": self.artifact_hash,
            "agent_kid": self.agent_kid,
            "tenant": self.tenant,
            "created_at": self.created_at,
        }


def compute_artifact_hash(body: dict) -> str:
    """Compute the sha256 hash of a JCS-canonicalized artifact body.

    This is the hash that goes into the Merkle tree. The same function
    is used for receipts (where it matches receipt_hash) and for agent
    artifacts (audit reports, proposals, etc.).
    """
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


class ArtifactLog:
    """Unified append-only log of all signed artifact hashes.

    The anchor scheduler reads from this log to build the unified
    Merkle tree. Each entry contains enough metadata to identify
    the artifact and its signing agent, but the actual artifact
    body lives in its own collection (receipts, audit_reports, etc.).
    """

    def __init__(self, tenant: str, firestore_client=None):
        self._tenant = tenant
        self._db = firestore_client
        self._memory: list[ArtifactEntry] = []
        self._seq = 0

        if self._db:
            self._resume_seq()

    def _collection(self):
        return self._db.collection("tenants").document(self._tenant) \
            .collection("artifact_log")

    def _resume_seq(self) -> None:
        """Resume sequence number from Firestore on startup."""
        try:
            docs = self._collection().order_by(
                "seq", direction="DESCENDING"
            ).limit(1).stream()
            for doc in docs:
                data = doc.to_dict()
                self._seq = data.get("seq", 0)
                logger.info("Artifact log resumed at seq=%d for tenant=%s", self._seq, self._tenant)
                return
        except Exception as e:
            logger.warning("Could not resume artifact log seq: %s", e)

    def append(
        self,
        artifact_type: str,
        artifact_id: str,
        artifact_hash: str,
        agent_kid: str,
    ) -> ArtifactEntry:
        """Append an artifact hash to the unified log."""
        self._seq += 1
        entry = ArtifactEntry(
            seq=self._seq,
            artifact_type=artifact_type,
            artifact_id=artifact_id,
            artifact_hash=artifact_hash,
            agent_kid=agent_kid,
            tenant=self._tenant,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        if self._db:
            doc_id = f"{self._seq:010d}"
            self._collection().document(doc_id).set(entry.to_dict())
        else:
            self._memory.append(entry)

        logger.debug(
            "Artifact log: seq=%d type=%s id=%s hash=%s",
            entry.seq, artifact_type, artifact_id, artifact_hash[:24],
        )
        return entry

    def get_entries_since(self, after_seq: int, limit: int = 500) -> list[ArtifactEntry]:
        """Get log entries after a given sequence number."""
        if self._db:
            entries = []
            docs = self._collection() \
                .where("seq", ">", after_seq) \
                .order_by("seq") \
                .limit(limit) \
                .stream()
            for doc in docs:
                d = doc.to_dict()
                entries.append(ArtifactEntry(**d))
            return entries

        return [e for e in self._memory if e.seq > after_seq][:limit]

    def get_all_hashes_since(self, after_seq: int) -> list[str]:
        """Get just the artifact hashes since a sequence number.

        These are the leaf inputs to the unified Merkle tree.
        """
        entries = self.get_entries_since(after_seq)
        return [e.artifact_hash for e in entries]

    @property
    def head_seq(self) -> int:
        return self._seq

    def get_entry(self, seq: int) -> ArtifactEntry | None:
        """Get a specific entry by sequence number."""
        if self._db:
            doc_id = f"{seq:010d}"
            doc = self._collection().document(doc_id).get()
            if doc.exists:
                return ArtifactEntry(**doc.to_dict())
            return None
        for e in self._memory:
            if e.seq == seq:
                return e
        return None
