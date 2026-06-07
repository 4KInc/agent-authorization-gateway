"""Resource registry — tenant-scoped resource identity management.

Each resource has a canonical ID, lifecycle status, and metadata.
The registry supports optional strict enforcement: when
require_resource_registration is true in the policy, the Gateway
rejects authorization for unregistered resources.

Modeled on gateway/identity.py (AgentRegistry).
"""

from __future__ import annotations

import logging
import re
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("gateway.resources")

_RESOURCE_ID_RE = re.compile(r"^[a-zA-Z0-9._/\-]{1,256}$")
_CACHE_TTL = 60  # seconds


class ResourceConflict(Exception):
    """Raised when registering a resource_id that is already active."""


def validate_resource_id(resource_id: str) -> None:
    if not resource_id or not _RESOURCE_ID_RE.match(resource_id):
        raise ValueError(
            f"resource_id must match [a-zA-Z0-9._/-]{{1,256}}, got '{resource_id[:64]}'"
        )


def _validate_display_name(display_name: str) -> None:
    if not display_name or len(display_name) > 256:
        raise ValueError("display_name is required and must be 1-256 characters")


class ResourceRegistry:
    """Tenant-scoped resource registry with Firestore persistence and LRU cache."""

    def __init__(self, tenant_id: str, firestore_client=None):
        self._tenant = tenant_id
        self._db = firestore_client
        self._cache: OrderedDict[str, tuple[bool, float]] = OrderedDict()
        self._cache_max = 1000
        if self._db:
            self._warm_cache()

    def _collection(self):
        return self._db.collection("tenants").document(self._tenant) \
            .collection("resources")

    def _warm_cache(self) -> None:
        try:
            count = 0
            for doc in self._collection().stream():
                data = doc.to_dict()
                rid = data.get("resource_id", doc.id)
                active = data.get("status") == "active"
                self._cache_put(rid, active)
                count += 1
            logger.info("[startup] Loaded %d resources into cache for tenant %s", count, self._tenant)
        except Exception as e:
            logger.warning("[startup] Could not load resources from Firestore: %s", e)

    def _cache_put(self, resource_id: str, active: bool) -> None:
        self._cache[resource_id] = (active, time.time())
        self._cache.move_to_end(resource_id)
        while len(self._cache) > self._cache_max:
            self._cache.popitem(last=False)

    def _cache_invalidate(self, resource_id: str) -> None:
        self._cache.pop(resource_id, None)

    def register(
        self,
        resource_id: str,
        display_name: str,
        description: str = "",
        resource_type: str = "",
        owner: str = "",
        metadata: dict | None = None,
        registered_by: str = "system",
        provenance: str = "manual",
    ) -> dict:
        validate_resource_id(resource_id)
        _validate_display_name(display_name)

        now = datetime.now(timezone.utc).isoformat()
        doc = {
            "resource_id": resource_id,
            "tenant_id": self._tenant,
            "display_name": display_name,
            "description": description,
            "resource_type": resource_type,
            "owner": owner,
            "metadata": metadata or {},
            "status": "active",
            "registered_at": now,
            "registered_by": registered_by,
            "revoked_at": None,
            "revoked_by": None,
            "version": 1,
            "provenance": provenance,
        }

        if self._db:
            existing = self._collection().document(resource_id).get()
            if existing.exists:
                data = existing.to_dict()
                if data.get("status") == "active":
                    raise ResourceConflict(
                        f"Resource '{resource_id}' is already registered and active. "
                        f"Revoke it first to re-register."
                    )
                # Re-registration after revocation: bump version
                doc["version"] = data.get("version", 1) + 1
            self._collection().document(resource_id).set(doc)
        else:
            # In-memory only (tests)
            if not hasattr(self, "_memory"):
                self._memory: dict[str, dict] = {}
            if resource_id in self._memory and self._memory[resource_id].get("status") == "active":
                raise ResourceConflict(
                    f"Resource '{resource_id}' is already registered and active."
                )
            if resource_id in self._memory:
                doc["version"] = self._memory[resource_id].get("version", 1) + 1
            self._memory[resource_id] = doc

        self._cache_put(resource_id, True)
        logger.info("Registered resource: %s tenant=%s by=%s", resource_id, self._tenant, registered_by)
        return doc

    def revoke(self, resource_id: str, revoked_by: str = "system") -> dict:
        now = datetime.now(timezone.utc).isoformat()

        if self._db:
            doc_ref = self._collection().document(resource_id)
            doc = doc_ref.get()
            if not doc.exists or doc.to_dict().get("status") != "active":
                raise ValueError(f"Resource '{resource_id}' is not actively registered")
            doc_ref.update({
                "status": "revoked",
                "revoked_at": now,
                "revoked_by": revoked_by,
            })
            result = doc_ref.get().to_dict()
        else:
            if not hasattr(self, "_memory"):
                self._memory = {}
            entry = self._memory.get(resource_id)
            if not entry or entry.get("status") != "active":
                raise ValueError(f"Resource '{resource_id}' is not actively registered")
            entry["status"] = "revoked"
            entry["revoked_at"] = now
            entry["revoked_by"] = revoked_by
            result = entry

        self._cache_put(resource_id, False)
        logger.info("Revoked resource: %s by=%s", resource_id, revoked_by)
        return result

    def update_verification(self, resource_id: str, status: str, reason: str | None) -> None:
        """Persist verification result as top-level fields on the resource doc."""
        fields = {"verification": status, "verification_reason": reason or ""}
        if self._db:
            self._collection().document(resource_id).update(fields)
        elif hasattr(self, "_memory") and resource_id in self._memory:
            self._memory[resource_id].update(fields)

    def get(self, resource_id: str) -> dict | None:
        if self._db:
            doc = self._collection().document(resource_id).get()
            return doc.to_dict() if doc.exists else None
        if hasattr(self, "_memory"):
            return self._memory.get(resource_id)
        return None

    def is_registered_and_active(self, resource_id: str) -> bool:
        # Check cache first
        if resource_id in self._cache:
            active, ts = self._cache[resource_id]
            if time.time() - ts < _CACHE_TTL:
                return active

        # Cache miss or stale — query Firestore
        if self._db:
            doc = self._collection().document(resource_id).get()
            if doc.exists:
                active = doc.to_dict().get("status") == "active"
                self._cache_put(resource_id, active)
                return active
            self._cache_put(resource_id, False)
            return False

        # In-memory mode
        if hasattr(self, "_memory"):
            entry = self._memory.get(resource_id)
            return entry is not None and entry.get("status") == "active"
        return False

    def list_all(
        self,
        include_revoked: bool = False,
        limit: int = 100,
        cursor: str | None = None,
    ) -> tuple[list[dict], str | None]:
        if self._db:
            all_docs = []
            for doc in self._collection().stream():
                data = doc.to_dict()
                if not include_revoked and data.get("status") != "active":
                    continue
                all_docs.append(data)
            all_docs.sort(key=lambda r: r.get("resource_id", ""))
            start = 0
            if cursor:
                for i, item in enumerate(all_docs):
                    if item.get("resource_id") == cursor:
                        start = i + 1
                        break
            page = all_docs[start:start + limit]
            next_cursor = page[-1]["resource_id"] if len(all_docs) > start + limit else None
            return page, next_cursor

        # In-memory fallback
        if not hasattr(self, "_memory"):
            return [], None
        all_items = sorted(self._memory.values(), key=lambda r: r.get("resource_id", ""))
        if not include_revoked:
            all_items = [r for r in all_items if r.get("status") == "active"]
        start = 0
        if cursor:
            for i, item in enumerate(all_items):
                if item.get("resource_id") == cursor:
                    start = i + 1
                    break
        page = all_items[start:start + limit]
        next_cursor = page[-1]["resource_id"] if len(all_items) > start + limit else None
        return page, next_cursor

    def update_metadata(
        self,
        resource_id: str,
        updated_by: str = "system",
        display_name: str | None = None,
        description: str | None = None,
        resource_type: str | None = None,
        owner: str | None = None,
        metadata: dict | None = None,
    ) -> dict:
        if self._db:
            doc_ref = self._collection().document(resource_id)
            doc = doc_ref.get()
            if not doc.exists:
                raise ValueError(f"Resource '{resource_id}' not found")
            data = doc.to_dict()
            if data.get("status") != "active":
                raise ValueError(f"Resource '{resource_id}' is revoked and cannot be updated")
        else:
            if not hasattr(self, "_memory"):
                self._memory = {}
            data = self._memory.get(resource_id)
            if not data:
                raise ValueError(f"Resource '{resource_id}' not found")
            if data.get("status") != "active":
                raise ValueError(f"Resource '{resource_id}' is revoked and cannot be updated")

        updates: dict[str, Any] = {"version": data.get("version", 1) + 1}
        if display_name is not None:
            _validate_display_name(display_name)
            updates["display_name"] = display_name
        if description is not None:
            updates["description"] = description
        if resource_type is not None:
            updates["resource_type"] = resource_type
        if owner is not None:
            updates["owner"] = owner
        if metadata is not None:
            updates["metadata"] = metadata

        if self._db:
            doc_ref.update(updates)
            result = doc_ref.get().to_dict()
        else:
            data.update(updates)
            result = data

        self._cache_invalidate(resource_id)
        self._cache_put(resource_id, True)
        logger.info("Updated resource metadata: %s by=%s v=%d", resource_id, updated_by, updates["version"])
        return result
