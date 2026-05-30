"""Four evidence-gathering tools for the Investigation Agent.

Each tool reads from Firestore (read-only). The Investigator never
modifies any data — it only synthesizes what it reads.
"""

from __future__ import annotations

import json
import logging
from typing import Dict, List, Optional

from google.cloud import firestore

logger = logging.getLogger(__name__)


class EvidenceCollector:
    def __init__(self, db: firestore.Client):
        self.db = db

    def get_receipt(self, tenant: str, seq: int) -> Optional[Dict]:
        collection = self.db.collection("tenants").document(tenant).collection("receipts")
        for doc in collection.stream():
            data = doc.to_dict()
            body = data.get("body", {})
            try:
                if int(body.get("seq", -1)) == seq:
                    return data
            except (ValueError, TypeError):
                continue
        return None

    def get_audit_report(self, tenant: str, audit_id: str) -> Optional[Dict]:
        doc = self.db.collection("tenants").document(tenant) \
            .collection("audit_reports").document(audit_id).get()
        return doc.to_dict() if doc.exists else None

    def get_agent_registration(self, tenant: str, agent_id: str) -> Optional[Dict]:
        doc = self.db.collection("tenants").document(tenant) \
            .collection("metadata").document("agent_registry").get()
        if not doc.exists:
            return None
        registry = doc.to_dict()
        agents = registry.get("agents", {})
        if agent_id in agents:
            return {"agent_id": agent_id, "status": "registered", **agents[agent_id]}
        return {"agent_id": agent_id, "status": "unregistered"}

    def get_recent_activity(self, tenant: str, agent_id: str, hours_back: int = 24) -> List[Dict]:
        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        cutoff_iso = cutoff.isoformat()

        collection = self.db.collection("tenants").document(tenant).collection("receipts")
        results = []
        for doc in collection.stream():
            data = doc.to_dict()
            body = data.get("body", {})
            meta = data.get("_meta", {})
            receipt_agent = meta.get("agent_id", body.get("sub", ""))
            ts = body.get("ts", "")
            if receipt_agent == agent_id and ts >= cutoff_iso:
                results.append(data)

        results.sort(key=lambda r: r.get("body", {}).get("ts", ""))
        return results

    def get_policy_proposal(self, tenant: str, proposal_id: str) -> Optional[Dict]:
        doc = self.db.collection("tenants").document(tenant) \
            .collection("policy_proposals").document(proposal_id).get()
        return doc.to_dict() if doc.exists else None


def make_adk_tools(collector: EvidenceCollector, tenant: str):
    """Create ADK-compatible tool functions bound to a tenant."""

    def get_receipt(seq: int) -> str:
        """Fetch a specific authorization receipt by sequence number.

        Args:
            seq: The receipt sequence number to fetch.

        Returns:
            JSON string of the receipt, or an error message.
        """
        result = collector.get_receipt(tenant, seq)
        if result is None:
            return json.dumps({"error": f"Receipt seq={seq} not found for tenant={tenant}"})
        return json.dumps(result, default=str)

    def get_audit_report(audit_id: str) -> str:
        """Fetch a specific audit report by its ID.

        Args:
            audit_id: The UUID of the audit report to fetch.

        Returns:
            JSON string of the audit report, or an error message.
        """
        result = collector.get_audit_report(tenant, audit_id)
        if result is None:
            return json.dumps({"error": f"Audit report {audit_id} not found for tenant={tenant}"})
        return json.dumps(result, default=str)

    def get_agent_registration(agent_id: str) -> str:
        """Look up an agent's registration status and key information.

        Args:
            agent_id: The agent identifier to look up.

        Returns:
            JSON string with agent registration details.
        """
        result = collector.get_agent_registration(tenant, agent_id)
        if result is None:
            return json.dumps({"agent_id": agent_id, "status": "unregistered"})
        return json.dumps(result, default=str)

    def get_recent_activity(agent_id: str, hours_back: int = 24) -> str:
        """Fetch recent authorization receipts for a specific agent.

        Args:
            agent_id: The agent identifier to search for.
            hours_back: How many hours back to search (default 24).

        Returns:
            JSON string with array of recent receipts for this agent.
        """
        results = collector.get_recent_activity(tenant, agent_id, hours_back)
        return json.dumps({"agent_id": agent_id, "hours_back": hours_back,
                           "count": len(results), "receipts": results}, default=str)

    def get_policy_proposal(proposal_id: str) -> str:
        """Fetch a specific policy proposal by its ID.

        Args:
            proposal_id: The UUID of the policy proposal to fetch.

        Returns:
            JSON string of the policy proposal, or an error message.
        """
        result = collector.get_policy_proposal(tenant, proposal_id)
        if result is None:
            return json.dumps({"error": f"Proposal {proposal_id} not found for tenant={tenant}"})
        return json.dumps(result, default=str)

    return [get_receipt, get_audit_report, get_agent_registration,
            get_recent_activity, get_policy_proposal]
