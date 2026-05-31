#!/usr/bin/env python3
"""Scan existing receipts, extract unique resource strings, bulk-register as resources.

Idempotent: safe to run multiple times. On conflict (resource already registered),
the script skips silently.

Usage:
    python3 scripts/migrate-resources-from-receipts.py --tenant=hackathon-demo [--dry-run]
"""
import argparse
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    parser = argparse.ArgumentParser(description="Migrate resources from receipt chain")
    parser.add_argument("--tenant", default="hackathon-demo")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be registered without writing")
    args = parser.parse_args()

    from google.cloud import firestore
    project = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", "quick-catcher-470218-b0"))
    db = firestore.Client(project=project)

    # Scan receipts for unique resource strings
    receipts_ref = db.collection("tenants").document(args.tenant).collection("receipts")
    unique_resources: set[str] = set()
    receipt_count = 0

    print(f"Scanning receipts for tenant '{args.tenant}'...")
    for doc in receipts_ref.stream():
        receipt_count += 1
        data = doc.to_dict()
        meta = data.get("_meta", {})
        resource = meta.get("resource", "")
        if resource and resource.strip():
            unique_resources.add(resource.strip())

    print(f"Found {len(unique_resources)} unique resources from {receipt_count} receipts.")

    if not unique_resources:
        print("Nothing to migrate.")
        return

    # Filter out resources with characters not allowed by the resource ID regex
    import re
    valid_re = re.compile(r"^[a-zA-Z0-9._/\-]{1,256}$")
    valid_resources = []
    skipped = []
    for r in sorted(unique_resources):
        if valid_re.match(r):
            valid_resources.append(r)
        else:
            skipped.append(r)

    if skipped:
        print(f"\nSkipping {len(skipped)} resources with invalid IDs:")
        for s in skipped:
            print(f"  SKIP: {s!r}")

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if args.dry_run:
        print(f"\n[DRY RUN] Would register {len(valid_resources)} resources:")
        for r in valid_resources:
            print(f"  + {r}")
        return

    # Register each resource
    from gateway.resources import ResourceConflict, ResourceRegistry
    registry = ResourceRegistry(tenant_id=args.tenant, firestore_client=db)

    registered = 0
    already_exists = 0
    for r in valid_resources:
        try:
            registry.register(
                resource_id=r,
                display_name=r,
                description=f"Auto-imported from receipt chain on {today}",
                provenance="imported_from_receipts",
                registered_by="system",
            )
            registered += 1
            print(f"  + Registered: {r}")
        except ResourceConflict:
            already_exists += 1
            print(f"  = Already exists: {r}")
        except Exception as e:
            print(f"  ! Error registering {r}: {e}")

    print(f"\nMigrated {registered} unique resources from {receipt_count} receipts.")
    if already_exists:
        print(f"Skipped {already_exists} already-registered resources.")


if __name__ == "__main__":
    main()
