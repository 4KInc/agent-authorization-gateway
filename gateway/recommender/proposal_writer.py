"""Signs and persists PolicyProposals to Firestore.

Each proposal is signed by the Recommender's own Ed25519 key (separate from
the Gateway and Auditor keys). Proposals are stored at
tenants/{tenant}/policy_proposals/{proposal_id}.
"""

from __future__ import annotations

import json
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
    sig = key.sign(_canonicalize(body))
    envelope = {
        "body": body,
        "signature": "ed25519:" + sig.hex(),
    }
    db.collection("tenants").document(tenant) \
        .collection("policy_proposals").document(proposal_id).set(envelope)
    return envelope
