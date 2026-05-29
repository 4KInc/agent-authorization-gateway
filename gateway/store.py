"""Receipt persistence — Firestore + in-memory fallback.

Stores receipts, keys, and chain metadata for durability and audit.
Falls back to in-memory storage when Firestore is not configured.
"""

from __future__ import annotations

import json
import os
import time
from abc import ABC, abstractmethod


class ReceiptStore(ABC):
    """Abstract receipt storage interface."""

    @abstractmethod
    async def save_receipt(self, tenant: str, receipt: dict) -> None: ...

    @abstractmethod
    async def get_receipt(self, tenant: str, receipt_hash: str) -> dict | None: ...

    @abstractmethod
    async def get_chain(self, tenant: str) -> list[dict]: ...

    @abstractmethod
    async def save_keys(self, tenant: str, keys: dict) -> None: ...

    @abstractmethod
    async def get_keys(self, tenant: str) -> dict | None: ...

    @abstractmethod
    async def save_stats(self, tenant: str, stats: dict) -> None: ...

    @abstractmethod
    async def get_stats(self, tenant: str) -> dict | None: ...

    @abstractmethod
    async def save_policy(self, tenant: str, policy: dict) -> None: ...

    @abstractmethod
    async def get_policy(self, tenant: str) -> dict | None: ...

    @abstractmethod
    async def save_rate_limits(self, tenant: str, counters: dict) -> None: ...

    @abstractmethod
    async def get_rate_limits(self, tenant: str) -> dict | None: ...

    @abstractmethod
    async def save_anchor_record(self, tenant: str, record: dict) -> None: ...

    @abstractmethod
    async def list_anchor_records(self, tenant: str) -> list[dict]: ...

    @abstractmethod
    async def get_anchor_record(self, tenant: str, tx_hash: str) -> dict | None: ...


class InMemoryStore(ReceiptStore):
    """In-memory receipt store for local development and testing."""

    def __init__(self):
        self._receipts: dict[str, list[dict]] = {}
        self._receipt_index: dict[str, dict] = {}
        self._keys: dict[str, dict] = {}
        self._stats: dict[str, dict] = {}

    async def save_receipt(self, tenant: str, receipt: dict) -> None:
        if tenant not in self._receipts:
            self._receipts[tenant] = []
        self._receipts[tenant].append(receipt)
        receipt_hash = receipt.get("receipt_hash", "")
        if receipt_hash:
            self._receipt_index[f"{tenant}:{receipt_hash}"] = receipt

    async def get_receipt(self, tenant: str, receipt_hash: str) -> dict | None:
        return self._receipt_index.get(f"{tenant}:{receipt_hash}")

    async def get_chain(self, tenant: str) -> list[dict]:
        return list(self._receipts.get(tenant, []))

    async def save_keys(self, tenant: str, keys: dict) -> None:
        self._keys[tenant] = keys

    async def get_keys(self, tenant: str) -> dict | None:
        return self._keys.get(tenant)

    async def save_stats(self, tenant: str, stats: dict) -> None:
        self._stats[tenant] = {**stats, "updated_at": time.time()}

    async def get_stats(self, tenant: str) -> dict | None:
        return self._stats.get(tenant)

    async def save_policy(self, tenant: str, policy: dict) -> None:
        self._stats[f"{tenant}:policy"] = policy

    async def get_policy(self, tenant: str) -> dict | None:
        return self._stats.get(f"{tenant}:policy")

    async def save_rate_limits(self, tenant: str, counters: dict) -> None:
        self._stats[f"{tenant}:rate_limits"] = counters

    async def get_rate_limits(self, tenant: str) -> dict | None:
        return self._stats.get(f"{tenant}:rate_limits")

    async def save_anchor_record(self, tenant: str, record: dict) -> None:
        key = f"{tenant}:anchors"
        if key not in self._stats:
            self._stats[key] = []
        self._stats[key].append(record)

    async def list_anchor_records(self, tenant: str) -> list[dict]:
        return list(reversed(self._stats.get(f"{tenant}:anchors", [])))

    async def get_anchor_record(self, tenant: str, tx_hash: str) -> dict | None:
        for r in self._stats.get(f"{tenant}:anchors", []):
            if r.get("tx_hash") == tx_hash:
                return r
        return None


class FirestoreStore(ReceiptStore):
    """Firestore-backed receipt store for production persistence."""

    def __init__(self, project_id: str | None = None):
        from google.cloud import firestore
        self._db = firestore.AsyncClient(project=project_id)

    async def save_receipt(self, tenant: str, receipt: dict) -> None:
        receipt_hash = receipt.get("receipt_hash", "unknown")
        doc_id = receipt_hash.removeprefix("sha256:")[:24]
        doc_ref = self._db.collection("tenants").document(tenant) \
            .collection("receipts").document(doc_id)
        await doc_ref.set(receipt)

    async def get_receipt(self, tenant: str, receipt_hash: str) -> dict | None:
        doc_id = receipt_hash.removeprefix("sha256:")[:24]
        doc_ref = self._db.collection("tenants").document(tenant) \
            .collection("receipts").document(doc_id)
        doc = await doc_ref.get()
        return doc.to_dict() if doc.exists else None

    async def get_chain(self, tenant: str) -> list[dict]:
        collection_ref = self._db.collection("tenants").document(tenant) \
            .collection("receipts")
        docs = collection_ref.order_by("body.seq").stream()
        receipts = []
        async for doc in docs:
            receipts.append(doc.to_dict())
        return receipts

    async def save_keys(self, tenant: str, keys: dict) -> None:
        doc_ref = self._db.collection("tenants").document(tenant) \
            .collection("metadata").document("keys")
        await doc_ref.set(keys)

    async def get_keys(self, tenant: str) -> dict | None:
        doc_ref = self._db.collection("tenants").document(tenant) \
            .collection("metadata").document("keys")
        doc = await doc_ref.get()
        return doc.to_dict() if doc.exists else None

    async def save_stats(self, tenant: str, stats: dict) -> None:
        doc_ref = self._db.collection("tenants").document(tenant) \
            .collection("metadata").document("stats")
        await doc_ref.set({**stats, "updated_at": time.time()})

    async def get_stats(self, tenant: str) -> dict | None:
        doc_ref = self._db.collection("tenants").document(tenant) \
            .collection("metadata").document("stats")
        doc = await doc_ref.get()
        return doc.to_dict() if doc.exists else None

    async def save_policy(self, tenant: str, policy: dict) -> None:
        doc_ref = self._db.collection("tenants").document(tenant) \
            .collection("metadata").document("policy")
        await doc_ref.set(policy)

    async def get_policy(self, tenant: str) -> dict | None:
        doc_ref = self._db.collection("tenants").document(tenant) \
            .collection("metadata").document("policy")
        doc = await doc_ref.get()
        return doc.to_dict() if doc.exists else None

    async def save_rate_limits(self, tenant: str, counters: dict) -> None:
        doc_ref = self._db.collection("tenants").document(tenant) \
            .collection("metadata").document("rate_limits")
        await doc_ref.set({**counters, "updated_at": time.time()})

    async def get_rate_limits(self, tenant: str) -> dict | None:
        doc_ref = self._db.collection("tenants").document(tenant) \
            .collection("metadata").document("rate_limits")
        doc = await doc_ref.get()
        return doc.to_dict() if doc.exists else None

    async def save_anchor_record(self, tenant: str, record: dict) -> None:
        tx_hash = record.get("tx_hash", "unknown")
        doc_id = tx_hash.replace("0x", "")[:24] if tx_hash.startswith("0x") else tx_hash[:24]
        doc_ref = self._db.collection("tenants").document(tenant) \
            .collection("anchors").document(doc_id)
        await doc_ref.set(record)

    async def list_anchor_records(self, tenant: str) -> list[dict]:
        collection_ref = self._db.collection("tenants").document(tenant) \
            .collection("anchors")
        docs = collection_ref.order_by("block_number", direction="DESCENDING").limit(50).stream()
        records = []
        async for doc in docs:
            records.append(doc.to_dict())
        return records

    async def get_anchor_record(self, tenant: str, tx_hash: str) -> dict | None:
        doc_id = tx_hash.replace("0x", "")[:24] if tx_hash.startswith("0x") else tx_hash[:24]
        doc_ref = self._db.collection("tenants").document(tenant) \
            .collection("anchors").document(doc_id)
        doc = await doc_ref.get()
        return doc.to_dict() if doc.exists else None


def create_store() -> ReceiptStore:
    """Create the appropriate store based on environment.

    Uses Firestore if FIRESTORE_ENABLED=true is set AND the database exists.
    Otherwise falls back to in-memory (safe default for hackathon).
    """
    if os.environ.get("FIRESTORE_ENABLED", "").lower() == "true":
        project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
        if project_id:
            try:
                store = FirestoreStore(project_id=project_id)
                print(f"[store] Using Firestore (project={project_id})")
                return store
            except Exception as e:
                print(f"[store] Firestore init failed ({e}), falling back to in-memory")
    print("[store] Using in-memory store")
    return InMemoryStore()
