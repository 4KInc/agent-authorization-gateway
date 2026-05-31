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

    def _collection(self):
        return self._db.collection("tenants").document(self._tenant).collection("actions")

    def register(
        self,
        action_id: str,
        display_name: str,
        description: str = "",
        risk_level: str = "low",
        requires_human_approval: bool = False,
        registered_by: str = "anonymous",
        metadata: dict | None = None,
    ) -> dict:
        validate_action_id(action_id)
        if not display_name or len(display_name) > 256:
            raise ValueError("display_name is required and must be 1-256 characters")

        now = datetime.now(timezone.utc).isoformat()

        if self._db:
            existing = self._collection().document(action_id).get()
            if existing.exists and existing.to_dict().get("status") == "active":
                raise ActionConflict(f"Action '{action_id}' is already registered")

        doc = {
            "tenant_id": self._tenant,
            "action_id": action_id,
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
            self._collection().document(action_id).set(doc)

        logger.info("Registered action: %s risk=%s tenant=%s", action_id, risk_level, self._tenant)
        return doc

    def get(self, action_id: str, include_revoked: bool = False) -> dict | None:
        if not self._db:
            return None
        doc = self._collection().document(action_id).get()
        if not doc.exists:
            return None
        data = doc.to_dict()
        if not include_revoked and data.get("status") != "active":
            return None
        return data

    def list_all(self, include_revoked: bool = False, limit: int = 100) -> list[dict]:
        if not self._db:
            return []
        actions = []
        for doc in self._collection().stream():
            data = doc.to_dict()
            if not include_revoked and data.get("status") != "active":
                continue
            actions.append(data)
        actions.sort(key=lambda a: a.get("action_id", ""))
        return actions[:limit]

    def revoke(self, action_id: str, revoked_by: str = "anonymous") -> dict:
        if not self._db:
            raise ValueError(f"Action '{action_id}' not found")
        doc = self._collection().document(action_id).get()
        if not doc.exists:
            raise ValueError(f"Action '{action_id}' not found")
        data = doc.to_dict()
        if data.get("status") != "active":
            raise ValueError(f"Action '{action_id}' is not active")
        now = datetime.now(timezone.utc).isoformat()
        self._collection().document(action_id).update({
            "status": "revoked",
            "revoked_at": now,
            "revoked_by": revoked_by,
        })
        data["status"] = "revoked"
        data["revoked_at"] = now
        return data

    def update(self, action_id: str, updates: dict) -> dict:
        if not self._db:
            raise ValueError(f"Action '{action_id}' not found")
        doc = self._collection().document(action_id).get()
        if not doc.exists:
            raise ValueError(f"Action '{action_id}' not found")
        data = doc.to_dict()
        if data.get("status") != "active":
            raise ValueError(f"Action '{action_id}' is not active")

        allowed = {"display_name", "description", "risk_level", "requires_human_approval", "metadata"}
        filtered = {k: v for k, v in updates.items() if k in allowed}
        if not filtered:
            return data

        filtered["version"] = data.get("version", 1) + 1
        self._collection().document(action_id).update(filtered)
        data.update(filtered)
        return data
