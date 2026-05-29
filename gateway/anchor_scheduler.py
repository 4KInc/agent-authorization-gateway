"""Background scheduler for on-chain anchoring to Base L2.

Triggers an anchor when either:
  - 10 new receipts have been issued since last anchor, OR
  - 1 hour has passed since last anchor (whichever comes first)

Runs as an asyncio background task in the REST gateway's lifespan.
Only the REST service runs this — MCP and ADK do not (no nonce races).
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("gateway.anchor_scheduler")

ANCHOR_RECEIPT_THRESHOLD = 10
ANCHOR_TIME_THRESHOLD_SECONDS = 3600  # 1 hour
POLL_INTERVAL_SECONDS = 300  # check every 5 minutes


async def anchor_loop(gateway, store):
    """Run forever. Check periodically whether to anchor."""
    from .base_anchor import anchor_root

    last_anchor_at: float | None = None
    last_anchor_head_seq: int = 0

    logger.info("Anchor scheduler started (threshold=%d receipts or %ds)",
                ANCHOR_RECEIPT_THRESHOLD, ANCHOR_TIME_THRESHOLD_SECONDS)

    while True:
        try:
            # Get current chain head
            receipts = gateway._receipt_chain.get_receipts()
            current_seq = len(receipts)

            receipts_since = current_seq - last_anchor_head_seq
            time_since = (time.time() - last_anchor_at) if last_anchor_at else float("inf")

            should_anchor = (
                receipts_since >= ANCHOR_RECEIPT_THRESHOLD
                or time_since >= ANCHOR_TIME_THRESHOLD_SECONDS
            )

            if should_anchor and current_seq > last_anchor_head_seq:
                merkle_root = gateway.get_merkle_root()
                if not merkle_root:
                    logger.debug("No receipts to anchor")
                    await asyncio.sleep(POLL_INTERVAL_SECONDS)
                    continue

                logger.info(
                    "Anchoring: root=%s seq=%d (receipts_since=%d, time_since=%.0fs)",
                    merkle_root[:24], current_seq, receipts_since, time_since,
                )

                # Run the blocking anchor_root in a thread executor
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None, anchor_root, merkle_root, current_seq,
                )

                # Persist anchor record to Firestore
                try:
                    from datetime import datetime, timezone
                    record = {
                        **result.to_dict(),
                        "anchored_at": datetime.now(timezone.utc).isoformat(),
                    }
                    await store.save_anchor_record(gateway.tenant, record)
                    logger.info("Anchor record saved: tx=%s block=%d", result.tx_hash, result.block_number)
                except Exception as e:
                    logger.error("Failed to save anchor record: %s", e)

                last_anchor_at = time.time()
                last_anchor_head_seq = current_seq

        except Exception as e:
            logger.error("Anchor cycle failed (will retry next cycle): %s", e, exc_info=True)

        await asyncio.sleep(POLL_INTERVAL_SECONDS)
