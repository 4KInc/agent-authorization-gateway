"""Background scheduler for on-chain anchoring to Base L2.

Anchors a unified Merkle root covering ALL signed artifacts:
- Receipts (from the Gateway)
- Audit reports (from the Auditor)
- Policy proposals (from the Recommender)
- Incident reports (from the Investigator)
- Isolation records (from the Isolator)

Triggers when either:
  - 10 new artifacts have been logged since last anchor, OR
  - 1 hour has passed since last anchor (whichever comes first)

The unified root is written to Base L2 as calldata. Anyone can verify
that any artifact was included in the tree at a specific block height.
"""

from __future__ import annotations

import asyncio
import logging
import time

from .artifact_log import ArtifactLog
from .merkle import compute_unified_root

logger = logging.getLogger("gateway.anchor_scheduler")

ANCHOR_ARTIFACT_THRESHOLD = 10
ANCHOR_TIME_THRESHOLD_SECONDS = 3600  # 1 hour
POLL_INTERVAL_SECONDS = 300  # check every 5 minutes


async def anchor_loop(gateway, store):
    """Run forever. Check periodically whether to anchor the unified tree."""
    from .base_anchor import anchor_root

    last_anchor_at: float | None = None
    last_anchor_seq: int = 0

    # Initialize artifact log
    firestore_db = None
    try:
        import os
        if os.environ.get("FIRESTORE_ENABLED", "").lower() == "true":
            from google.cloud import firestore
            firestore_db = firestore.Client(project=os.environ.get("GOOGLE_CLOUD_PROJECT"))
    except Exception:
        pass

    art_log = ArtifactLog(tenant=gateway.tenant, firestore_client=firestore_db)
    last_anchor_seq = art_log.head_seq  # Don't re-anchor old artifacts on restart

    logger.info(
        "Unified anchor scheduler started (threshold=%d artifacts or %ds, "
        "artifact_log head_seq=%d)",
        ANCHOR_ARTIFACT_THRESHOLD, ANCHOR_TIME_THRESHOLD_SECONDS, last_anchor_seq,
    )

    while True:
        try:
            current_seq = art_log.head_seq
            artifacts_since = current_seq - last_anchor_seq
            time_since = (time.time() - last_anchor_at) if last_anchor_at else float("inf")

            should_anchor = (
                artifacts_since >= ANCHOR_ARTIFACT_THRESHOLD
                or time_since >= ANCHOR_TIME_THRESHOLD_SECONDS
            )

            if should_anchor and artifacts_since > 0:
                # Collect all artifact hashes since last anchor
                hashes = art_log.get_all_hashes_since(last_anchor_seq)
                if not hashes:
                    await asyncio.sleep(POLL_INTERVAL_SECONDS)
                    continue

                # Strip "sha256:" prefix for Merkle computation
                hex_hashes = [h.removeprefix("sha256:") for h in hashes]
                unified_root = compute_unified_root(hex_hashes)

                logger.info(
                    "Anchoring unified root: root=%s artifacts=%d (seq %d→%d, time_since=%.0fs)",
                    unified_root[:24], len(hashes),
                    last_anchor_seq, current_seq, time_since,
                )

                # Submit to Base L2
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None, anchor_root, unified_root, current_seq,
                )

                # Persist anchor record
                try:
                    from datetime import datetime, timezone
                    record = {
                        **result.to_dict(),
                        "anchor_type": "unified",
                        "artifact_count": len(hashes),
                        "artifact_seq_range": [last_anchor_seq + 1, current_seq],
                        "anchored_at": datetime.now(timezone.utc).isoformat(),
                    }
                    await store.save_anchor_record(gateway.tenant, record)
                    logger.info(
                        "Unified anchor saved: tx=%s block=%d artifacts=%d",
                        result.tx_hash, result.block_number, len(hashes),
                    )
                except Exception as e:
                    logger.error("Failed to save anchor record: %s", e)

                last_anchor_at = time.time()
                last_anchor_seq = current_seq

        except Exception as e:
            logger.error("Anchor cycle failed (will retry): %s", e, exc_info=True)

        await asyncio.sleep(POLL_INTERVAL_SECONDS)
