"""Signs and persists IsolationRecords to Firestore.

Each record documents the quarantine of a rogue agent: which agent was
isolated, why, what evidence triggered it, and what containment actions
were taken. Signed by the Isolator's own Ed25519 key.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict

from google.cloud import firestore

from .isolator_signing_key import load as load_key


def _canonicalize(d: Dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def write_isolation_record(
    db: firestore.Client,
    tenant: str,
    agent_id: str,
    trigger: Dict,
    actions_taken: list[Dict],
    reason: str,
    severity: str,
    evidence_references: Dict,
) -> Dict:
    key = load_key()
    isolation_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    body = {
        "isolation_id": isolation_id,
        "tenant": tenant,
        "isolated_at": now,
        "agent_id": agent_id,
        "severity": severity,
        "trigger": trigger,
        "reason": reason,
        "actions_taken": actions_taken,
        "evidence_references": evidence_references,
        "schema_version": "isolation-record-v0.1",
        "isolator_kid": key.kid,
    }
    body_bytes = _canonicalize(body)
    sig = key.sign(body_bytes)
    artifact_hash = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
    envelope = {
        "body": body,
        "signature": "ed25519:" + sig.hex(),
        "artifact_hash": artifact_hash,
    }
    db.collection("tenants").document(tenant) \
        .collection("isolation_records").document(isolation_id).set(envelope)

    try:
        from ..artifact_log import ArtifactLog
        log = ArtifactLog(tenant=tenant, firestore_client=db)
        log.append(
            artifact_type="isolation_record",
            artifact_id=isolation_id,
            artifact_hash=artifact_hash,
            agent_kid=key.kid,
        )
    except Exception as e:
        logging.getLogger(__name__).warning("Artifact log append failed (non-fatal): %s", e)

    return envelope
