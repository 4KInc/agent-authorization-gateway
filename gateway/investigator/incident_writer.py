"""Signs and persists IncidentReports to Firestore.

Each report is signed by the Investigator's own Ed25519 key (separate from
the Gateway, Auditor, and Recommender keys). Reports are stored at
tenants/{tenant}/incident_reports/{incident_id}.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict

from google.cloud import firestore

from .investigator_signing_key import load as load_key


def _canonicalize(d: Dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def write_incident_report(
    db: firestore.Client,
    tenant: str,
    trigger: Dict,
    narrative: Dict,
) -> Dict:
    key = load_key()
    incident_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    body = {
        "incident_id": incident_id,
        "tenant": tenant,
        "created_at": now,
        "severity": narrative.get("severity", "MEDIUM"),
        "trigger": trigger,
        "narrative": narrative.get("narrative", {}),
        "evidence_references": narrative.get("evidence_references", {
            "receipts": [], "audit_reports": [], "policy_proposals": [],
        }),
        "schema_version": "incident-report-v0.1",
        "investigator_kid": key.kid,
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
        .collection("incident_reports").document(incident_id).set(envelope)

    try:
        from ..artifact_log import ArtifactLog
        log = ArtifactLog(tenant=tenant, firestore_client=db)
        log.append(
            artifact_type="incident_report",
            artifact_id=incident_id,
            artifact_hash=artifact_hash,
            agent_kid=key.kid,
        )
    except Exception as e:
        logging.getLogger(__name__).warning("Artifact log append failed (non-fatal): %s", e)

    return envelope
