"""Signs and persists IsolationRecords to Firestore.

Each record documents the quarantine of a rogue agent: which agent was
isolated, why, what evidence triggered it, and what containment actions
were taken. Signed by the Isolator's own Ed25519 key.
"""

from __future__ import annotations

import json
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
    sig = key.sign(_canonicalize(body))
    envelope = {
        "body": body,
        "signature": "ed25519:" + sig.hex(),
    }
    db.collection("tenants").document(tenant) \
        .collection("isolation_records").document(isolation_id).set(envelope)
    return envelope
