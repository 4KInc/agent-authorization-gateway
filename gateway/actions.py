"""Action registry — tenant-scoped action identity management.

Each action has a canonical ID, risk level, lifecycle status, and metadata.
The registry supports optional strict enforcement: when
require_action_registration is true in the policy, the Gateway
rejects authorization for unregistered actions.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger("gateway.actions")

_ACTION_ID_RE = re.compile(r"^[a-zA-Z0-9._/\-]{1,256}$")


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


VALID_RESOURCE_TYPES = {"db"}  # extensible in v0.6+


def _doc_key(action_id: str, resource_type: str) -> str:
    """Composite document key: action_id__resource_type."""
    return f"{action_id}__{resource_type}"


class ActionConflict(Exception):
    """Raised when registering an action_id that is already active."""


def validate_action_id(action_id: str) -> None:
    if not action_id or not _ACTION_ID_RE.match(action_id):
        raise ValueError(f"action_id must match [a-zA-Z0-9._/-]{{1,256}}, got '{action_id[:64]}'")


class ActionRegistry:
    """Tenant-scoped action registry with Firestore persistence."""

    def __init__(self, tenant_id: str, firestore_client=None):
        self._tenant = tenant_id
        self._db = firestore_client
        self._memory: dict[str, dict] = {}  # in-memory fallback for tests

    def _collection(self):
        return self._db.collection("tenants").document(self._tenant).collection("actions")

    def register(
        self,
        action_id: str,
        display_name: str,
        resource_type: str = "db",
        description: str = "",
        risk_level: str = "low",
        requires_human_approval: bool = False,
        registered_by: str = "anonymous",
        metadata: dict | None = None,
    ) -> dict:
        validate_action_id(action_id)
        if not display_name or len(display_name) > 256:
            raise ValueError("display_name is required and must be 1-256 characters")
        if resource_type not in VALID_RESOURCE_TYPES:
            raise ValueError(f"resource_type must be one of {sorted(VALID_RESOURCE_TYPES)}, got '{resource_type}'")

        now = datetime.now(timezone.utc).isoformat()
        doc_id = _doc_key(action_id, resource_type)

        if self._db:
            existing = self._collection().document(doc_id).get()
            if existing.exists and existing.to_dict().get("status") == "active":
                raise ActionConflict(f"Action '{action_id}' for resource_type '{resource_type}' is already registered")
        elif doc_id in self._memory and self._memory[doc_id].get("status") == "active":
            raise ActionConflict(f"Action '{action_id}' for resource_type '{resource_type}' is already registered")

        doc = {
            "tenant_id": self._tenant,
            "action_id": action_id,
            "resource_type": resource_type,
            "display_name": display_name,
            "description": description,
            "risk_level": risk_level,
            "requires_human_approval": requires_human_approval,
            "status": "active",
            "registered_at": now,
            "registered_by": registered_by,
            "version": 1,
            "metadata": metadata or {},
        }

        if self._db:
            self._collection().document(doc_id).set(doc)
        else:
            self._memory[doc_id] = doc

        logger.info("Registered action: %s resource_type=%s risk=%s tenant=%s", action_id, resource_type, risk_level, self._tenant)
        return doc

    def get(self, action_id: str, resource_type: str | None = None, include_revoked: bool = False) -> dict | None:
        if self._db:
            return self._get_firestore(action_id, resource_type, include_revoked)
        return self._get_memory(action_id, resource_type, include_revoked)

    def _get_memory(self, action_id: str, resource_type: str | None, include_revoked: bool) -> dict | None:
        if resource_type:
            data = self._memory.get(_doc_key(action_id, resource_type))
        else:
            data = self._memory.get(action_id)
            if not data:
                for rt in VALID_RESOURCE_TYPES:
                    data = self._memory.get(_doc_key(action_id, rt))
                    if data:
                        break
        if data and (include_revoked or data.get("status") == "active"):
            return data
        return None

    def _get_firestore(self, action_id: str, resource_type: str | None, include_revoked: bool) -> dict | None:
        if resource_type:
            doc = self._collection().document(_doc_key(action_id, resource_type)).get()
            if doc.exists:
                data = doc.to_dict()
                if include_revoked or data.get("status") == "active":
                    return data
            return None
        # Fallback: try legacy key then composite keys
        doc = self._collection().document(action_id).get()
        if doc.exists:
            data = doc.to_dict()
            if include_revoked or data.get("status") == "active":
                return data
        for rt in VALID_RESOURCE_TYPES:
            doc = self._collection().document(_doc_key(action_id, rt)).get()
            if doc.exists:
                data = doc.to_dict()
                if include_revoked or data.get("status") == "active":
                    return data
        return None

    def list_all(self, include_revoked: bool = False, limit: int = 100,
                 resource_type: str | None = None) -> list[dict]:
        if self._db:
            source = (doc.to_dict() for doc in self._collection().stream())
        else:
            source = self._memory.values()
        actions = []
        for data in source:
            if not include_revoked and data.get("status") != "active":
                continue
            if resource_type and data.get("resource_type") != resource_type:
                continue
            actions.append(data)
        actions.sort(key=lambda a: (a.get("resource_type", ""), a.get("action_id", "")))
        return actions[:limit]

    def revoke(self, action_id: str, resource_type: str | None = None, revoked_by: str = "anonymous") -> dict:
        if not self._db:
            raise ValueError(f"Action '{action_id}' not found")
        doc_id = _doc_key(action_id, resource_type) if resource_type else action_id
        doc = self._collection().document(doc_id).get()
        if not doc.exists and resource_type:
            # Try legacy key
            doc = self._collection().document(action_id).get()
        if not doc.exists:
            raise ValueError(f"Action '{action_id}' not found")
        data = doc.to_dict()
        if data.get("status") != "active":
            raise ValueError(f"Action '{action_id}' is not active")
        now = datetime.now(timezone.utc).isoformat()
        self._collection().document(doc.id).update({
            "status": "revoked",
            "revoked_at": now,
            "revoked_by": revoked_by,
        })
        data["status"] = "revoked"
        data["revoked_at"] = now
        return data

    def update(self, action_id: str, updates: dict, resource_type: str | None = None) -> dict:
        if not self._db:
            raise ValueError(f"Action '{action_id}' not found")
        doc_id = _doc_key(action_id, resource_type) if resource_type else action_id
        doc = self._collection().document(doc_id).get()
        if not doc.exists and resource_type:
            doc = self._collection().document(action_id).get()
        if not doc.exists:
            raise ValueError(f"Action '{action_id}' not found")
        data = doc.to_dict()
        if data.get("status") != "active":
            raise ValueError(f"Action '{action_id}' is not active")

        allowed = {"display_name", "description", "risk_level", "requires_human_approval", "metadata", "resource_type"}
        filtered = {k: v for k, v in updates.items() if k in allowed}
        if not filtered:
            return data

        filtered["version"] = data.get("version", 1) + 1
        self._collection().document(doc.id).update(filtered)
        data.update(filtered)
        return data
