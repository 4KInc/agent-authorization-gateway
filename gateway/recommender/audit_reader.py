"""Reads audit reports and existing proposals from Firestore.

Provides the two ADK FunctionTools the Recommender Agent uses:
  - get_audit_reports_window(hours_back)
  - get_recent_proposals(days_back)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from google.cloud import firestore

logger = logging.getLogger(__name__)


def fetch_audit_reports(db: firestore.Client, tenant: str, hours_back: int = 24) -> List[Dict]:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
    collection = db.collection("tenants").document(tenant).collection("audit_reports")
    reports = []
    for doc in collection.stream():
        data = doc.to_dict()
        body = data.get("body", {})
        if body.get("audited_at", "") >= cutoff:
            reports.append(data)
    reports.sort(key=lambda r: r.get("body", {}).get("audited_at", ""))
    return reports


def fetch_recent_proposals(db: firestore.Client, tenant: str, days_back: int = 7) -> List[Dict]:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days_back)).isoformat()
    collection = db.collection("tenants").document(tenant).collection("policy_proposals")
    proposals = []
    for doc in collection.stream():
        data = doc.to_dict()
        body = data.get("body", {})
        if body.get("proposed_at", "") >= cutoff:
            proposals.append(data)
    proposals.sort(key=lambda r: r.get("body", {}).get("proposed_at", ""))
    return proposals


def make_adk_tools(db: firestore.Client, tenant: str):
    """Create ADK FunctionTools for the Recommender Agent."""
    from google.adk.tools import FunctionTool

    def get_audit_reports_window(hours_back: int = 24) -> str:
        """Fetch audit reports from the last N hours. Returns a JSON array
        of audit report envelopes with body.verdict, body.rationale,
        body.citations, body.receipt_seq, body.audit_id, etc.

        Use this to find CONFLICT verdicts and patterns across ALIGNED verdicts.
        """
        try:
            reports = fetch_audit_reports(db, tenant, hours_back)
        except Exception as e:
            logger.warning("Failed to fetch audit reports: %s", e)
            return json.dumps({"error": str(e)})
        return json.dumps([r.get("body", {}) for r in reports], default=str)

    def get_recent_proposals(days_back: int = 7) -> str:
        """Fetch policy proposals from the last N days. Returns a JSON array
        of proposal envelopes. Use this to deduplicate: do NOT propose
        the same change that was already proposed recently.
        """
        try:
            proposals = fetch_recent_proposals(db, tenant, days_back)
        except Exception as e:
            logger.warning("Failed to fetch proposals: %s", e)
            return json.dumps({"error": str(e)})
        return json.dumps([p.get("body", {}) for p in proposals], default=str)

    return [FunctionTool(get_audit_reports_window), FunctionTool(get_recent_proposals)]
