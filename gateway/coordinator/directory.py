"""Firestore CRUD for the AgentDirectoryEntry collection.

Entries stored at: discovery_coordinator/agents/{agent_card_url_hash}
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from google.cloud import firestore

logger = logging.getLogger(__name__)


def _url_hash(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def _canonicalize(d: Dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def upsert_entry(db: firestore.Client, entry: Dict) -> Dict:
    """Insert or update an agent directory entry."""
    url = entry["agent_card_url"]
    doc_id = _url_hash(url)
    db.collection("discovery_coordinator").document("agents") \
        .collection("entries").document(doc_id).set(entry)
    logger.info("Upserted directory entry for %s (doc=%s)", url, doc_id)
    return entry


def get_entry(db: firestore.Client, agent_card_url: str) -> Optional[Dict]:
    doc_id = _url_hash(agent_card_url)
    doc = db.collection("discovery_coordinator").document("agents") \
        .collection("entries").document(doc_id).get()
    return doc.to_dict() if doc.exists else None


def list_entries(db: firestore.Client) -> List[Dict]:
    collection = db.collection("discovery_coordinator").document("agents") \
        .collection("entries")
    entries = []
    for doc in collection.stream():
        entries.append(doc.to_dict())
    entries.sort(key=lambda e: e.get("discovered_at", ""))
    return entries


def update_health(db: firestore.Client, agent_card_url: str, status: str) -> None:
    doc_id = _url_hash(agent_card_url)
    db.collection("discovery_coordinator").document("agents") \
        .collection("entries").document(doc_id).update({
            "last_health_check": datetime.now(timezone.utc).isoformat(),
            "health_status": status,
        })
