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


def create_store() -> ReceiptStore:
    """Create the appropriate store based on environment.

    Uses Firestore if GOOGLE_CLOUD_PROJECT is set, otherwise in-memory.
    """
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if project_id:
        try:
            return FirestoreStore(project_id=project_id)
        except Exception:
            pass
    return InMemoryStore()
