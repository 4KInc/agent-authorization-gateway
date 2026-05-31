#!/usr/bin/env python3
"""Snapshot Firestore document counts for a tenant.

Usage:
    python3 scripts/snapshot-firestore-state.py --tenant=hackathon-demo
"""
import argparse, json, os
from datetime import datetime, timezone
from google.cloud import firestore

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", default="hackathon-demo")
    args = parser.parse_args()

    project = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", "quick-catcher-470218-b0"))
    db = firestore.Client(project=project)
    tenant_ref = db.collection("tenants").document(args.tenant)

    collections = ["receipts", "audit_reports", "policy_proposals", "incident_reports", "agent_registry"]
    counts = {}
    for name in collections:
        count = 0
        for _ in tenant_ref.collection(name).select([]).limit(10000).stream():
            count += 1
        counts[name] = count

    snapshot = {
        "tenant": args.tenant,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
    }
    print(json.dumps(snapshot, indent=2))

if __name__ == "__main__":
    main()
