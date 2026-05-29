"""Reads unaudited receipts from Firestore.

The Auditor tracks per-tenant audit checkpoints (the latest receipt seq
it has audited) and reads forward from there on each tick.
"""

from __future__ import annotations

import logging
from typing import List, Dict

from google.cloud import firestore

logger = logging.getLogger(__name__)


class ReceiptReader:
    def __init__(self, db: firestore.Client):
        self.db = db

    def get_checkpoint(self, tenant: str) -> int:
        doc = self.db.collection("tenants").document(tenant) \
            .collection("auditor_state").document("checkpoint").get()
        if not doc.exists:
            return 0
        return doc.to_dict().get("last_audited_seq", 0)

    def set_checkpoint(self, tenant: str, seq: int) -> None:
        self.db.collection("tenants").document(tenant) \
            .collection("auditor_state").document("checkpoint").set({
                "last_audited_seq": seq,
            })

    def fetch_unaudited(self, tenant: str, max_batch: int = 10) -> List[Dict]:
        """Return up to max_batch receipts with seq > checkpoint.

        Note: Firestore stores seq as a string in the receipt body, so we
        load the full chain and filter in Python. For production scale,
        a numeric seq index would be needed.
        """
        checkpoint = self.get_checkpoint(tenant)
        # Load all receipts and filter (demo scale)
        collection = self.db.collection("tenants").document(tenant).collection("receipts")
        receipts = []
        for doc in collection.stream():
            data = doc.to_dict()
            body = data.get("body", {})
            try:
                seq = int(body.get("seq", "0"))
            except (ValueError, TypeError):
                continue
            if seq > checkpoint:
                # Flatten for the auditor: merge body + _meta
                flat = {**body}
                meta = data.get("_meta", {})
                flat.update(meta)
                flat["receipt_hash"] = data.get("receipt_hash", "")
                flat["_doc_id"] = doc.id
                receipts.append(flat)

        receipts.sort(key=lambda r: int(r.get("seq", 0)))
        return receipts[:max_batch]


def list_tenants(db: firestore.Client) -> List[str]:
    return [t.id for t in db.collection("tenants").list_documents()]
