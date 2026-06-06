#!/usr/bin/env python3
"""Migrate existing actions to include resource_type="db" with composite key.

For each existing action at tenants/{tenant}/actions/{action_id}:
1. Read the doc
2. Add resource_type="db"
3. Write new doc at tenants/{tenant}/actions/{action_id}__db
4. Delete the old doc

Idempotent: if the new doc already exists, skip.

Usage:
    python3 scripts/migrate-actions-add-resource-type.py --tenant=hackathon-demo [--dry-run]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", default="hackathon-demo")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    from google.cloud import firestore
    project = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", "quick-catcher-470218-b0"))
    db = firestore.Client(project=project)

    actions_ref = db.collection("tenants").document(args.tenant).collection("actions")
    migrated = 0
    skipped = 0
    already_composite = 0

    for doc in actions_ref.stream():
        data = doc.to_dict()
        action_id = data.get("action_id", doc.id)
        doc_id = doc.id

        # Already a composite key?
        if "__" in doc_id:
            already_composite += 1
            continue

        # Already has resource_type in the data?
        rt = data.get("resource_type", "")

        new_doc_id = f"{action_id}__db"

        # Check if new doc already exists
        new_doc = actions_ref.document(new_doc_id).get()
        if new_doc.exists:
            print(f"  SKIP {action_id}: {new_doc_id} already exists")
            skipped += 1
            continue

        if args.dry_run:
            print(f"  [DRY] Would migrate {doc_id} -> {new_doc_id}")
            migrated += 1
            continue

        # Write new doc with resource_type
        new_data = {**data, "resource_type": "db"}
        actions_ref.document(new_doc_id).set(new_data)

        # Delete old doc
        actions_ref.document(doc_id).delete()

        print(f"  MIGRATED {doc_id} -> {new_doc_id}")
        migrated += 1

    print(f"\nDone. Migrated: {migrated}, Skipped: {skipped}, Already composite: {already_composite}")


if __name__ == "__main__":
    main()
