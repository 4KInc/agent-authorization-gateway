"""Persists audit reports to Firestore.

Each report is signed by the Auditor's own Ed25519 key (separate from
the gateway signing key). Reports reference the audited receipt via
receipt_seq and receipt_hash.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Literal

from google.cloud import firestore

from .audit_signing_key import load as load_key

Verdict = Literal["ALIGNED", "CONFLICT", "INSUFFICIENT_EVIDENCE", "ERROR"]


def _canonicalize(d: Dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def write_audit_report(
    db: firestore.Client,
    tenant: str,
    receipt: Dict,
    verdict: Verdict,
    rationale: str,
    citations: List[Dict],
) -> Dict:
    key = load_key()
    audit_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    receipt_seq = int(receipt.get("seq", 0))
    receipt_hash = receipt.get("receipt_hash", "")

    body = {
        "audit_id": audit_id,
        "tenant": tenant,
        "receipt_seq": receipt_seq,
        "receipt_hash": receipt_hash,
        "verdict": verdict,
        "rationale": rationale,
        "citations": citations,
        "audited_at": now,
        "auditor_kid": key.kid,
        "schema_version": "auditor-v0.1",
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
        .collection("audit_reports").document(audit_id).set(envelope)

    # Register in gateway's unified artifact log for Merkle anchoring
    try:
        import os
        import httpx
        gateway_url = os.environ.get("GATEWAY_REST_URL", "http://localhost:8080")
        httpx.post(
            f"{gateway_url}/artifacts/register",
            json={
                "artifact_type": "audit_report",
                "artifact_id": audit_id,
                "artifact_hash": artifact_hash,
                "agent_kid": key.kid,
            },
            timeout=10,
        )
    except Exception as e:
        logging.getLogger(__name__).warning("Artifact log register failed (non-fatal): %s", e)

    return envelope
