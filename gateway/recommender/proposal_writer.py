"""Signs and persists PolicyProposals to Firestore.

Each proposal is signed by the Recommender's own Ed25519 key (separate from
the Gateway and Auditor keys). Proposals are stored at
tenants/{tenant}/policy_proposals/{proposal_id}.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict

from google.cloud import firestore

from .recommender_signing_key import load as load_key


def _canonicalize(d: Dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def write_proposal(
    db: firestore.Client,
    tenant: str,
    raw_proposal: Dict,
) -> Dict:
    key = load_key()
    proposal_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    body = {
        "proposal_id": proposal_id,
        "tenant": tenant,
        "proposed_at": now,
        "trigger": raw_proposal.get("trigger", {}),
        "proposed_change": raw_proposal.get("proposed_change", {}),
        "confidence": raw_proposal.get("confidence", "LOW"),
        "human_review_required": True,
        "schema_version": "policy-proposal-v0.1",
        "recommender_kid": key.kid,
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
        .collection("policy_proposals").document(proposal_id).set(envelope)

    try:
        from ..artifact_log import ArtifactLog
        log = ArtifactLog(tenant=tenant, firestore_client=db)
        log.append(
            artifact_type="policy_proposal",
            artifact_id=proposal_id,
            artifact_hash=artifact_hash,
            agent_kid=key.kid,
        )
    except Exception as e:
        logging.getLogger(__name__).warning("Artifact log append failed (non-fatal): %s", e)

    return envelope
