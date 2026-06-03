"""Async evidence buffer — decouples authorization decisions from Firestore persistence.

Hot path optimization: the authorize endpoint returns immediately after
cryptographic receipt signing. Firestore writes (receipt, stats, rate limits)
are queued and drained by a background task.

Enable with HOT_PATH_MODE=async (default is "sync" for backward compat).
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger("gateway.evidence_buffer")


@dataclass
class EvidenceItem:
    """A single unit of evidence to persist."""
    kind: str  # "receipt", "stats", "rate_limits"
    tenant: str
    payload: dict
    enqueued_at: float = field(default_factory=time.time)


class EvidenceBuffer:
    """Async buffer that decouples evidence production from Firestore writes.

    Evidence items are enqueued on the hot path (non-blocking) and drained
    to Firestore by a background asyncio task.
    """

    def __init__(
        self,
        store,  # ReceiptStore
        flush_interval: float = 1.0,
        max_batch_size: int = 10,
    ):
        self._store = store
        self._flush_interval = flush_interval
        self._max_batch_size = max_batch_size
        self._queue: asyncio.Queue[EvidenceItem] = asyncio.Queue()
        self._drain_task: asyncio.Task | None = None
        self._flush_count: int = 0
        self._flush_errors: int = 0
        self._total_enqueued: int = 0
        self._total_persisted: int = 0
        self._last_flush_at: float = 0.0
        self._shutting_down: bool = False

    @property
    def pending_count(self) -> int:
        return self._queue.qsize()

    @property
    def stats(self) -> dict:
        return {
            "mode": "async",
            "pending": self.pending_count,
            "total_enqueued": self._total_enqueued,
            "total_persisted": self._total_persisted,
            "flush_count": self._flush_count,
            "flush_errors": self._flush_errors,
            "last_flush_at": self._last_flush_at,
        }

    def enqueue(self, kind: str, tenant: str, payload: dict) -> None:
        """Non-blocking enqueue. Called on the hot path."""
        self._queue.put_nowait(EvidenceItem(kind=kind, tenant=tenant, payload=payload))
        self._total_enqueued += 1

    def start(self) -> None:
        """Start the background drain task."""
        if self._drain_task is None or self._drain_task.done():
            self._drain_task = asyncio.create_task(self._drain_loop())
            logger.info(
                "Evidence buffer started (flush_interval=%.1fs, max_batch=%d)",
                self._flush_interval,
                self._max_batch_size,
            )

    async def stop(self) -> None:
        """Flush remaining items and stop the drain task."""
        self._shutting_down = True
        if self._drain_task and not self._drain_task.done():
            self._drain_task.cancel()
            try:
                await self._drain_task
            except asyncio.CancelledError:
                pass
        # Final flush
        await self.flush()
        logger.info(
            "Evidence buffer stopped (persisted=%d, errors=%d)",
            self._total_persisted,
            self._flush_errors,
        )

    async def flush(self) -> int:
        """Force-drain all pending items. Returns count persisted."""
        count = 0
        while not self._queue.empty():
            batch = self._collect_batch(self._queue.qsize())
            if batch:
                await self._persist_batch(batch)
                count += len(batch)
        return count

    def _collect_batch(self, max_items: int | None = None) -> list[EvidenceItem]:
        """Collect up to max_items from the queue (non-blocking)."""
        limit = min(max_items or self._max_batch_size, self._max_batch_size)
        batch: list[EvidenceItem] = []
        for _ in range(limit):
            try:
                item = self._queue.get_nowait()
                batch.append(item)
            except asyncio.QueueEmpty:
                break
        return batch

    async def _persist_batch(self, batch: list[EvidenceItem]) -> None:
        """Persist a batch of evidence items to the store."""
        for item in batch:
            try:
                if item.kind == "receipt":
                    await self._store.save_receipt(item.tenant, item.payload)
                elif item.kind == "stats":
                    await self._store.save_stats(item.tenant, item.payload)
                elif item.kind == "rate_limits":
                    await self._store.save_rate_limits(item.tenant, item.payload)
                self._total_persisted += 1
            except Exception as e:
                self._flush_errors += 1
                logger.error("Evidence persist failed (%s): %s", item.kind, e)
        self._flush_count += 1
        self._last_flush_at = time.time()

    async def _drain_loop(self) -> None:
        """Background loop: drain queue to Firestore at flush_interval."""
        try:
            while True:
                # Wait for either an item or the flush interval
                try:
                    item = await asyncio.wait_for(
                        self._queue.get(), timeout=self._flush_interval
                    )
                    batch = [item]
                    # Collect more if available
                    batch.extend(self._collect_batch(self._max_batch_size - 1))
                except asyncio.TimeoutError:
                    batch = self._collect_batch()

                if batch:
                    await self._persist_batch(batch)
        except asyncio.CancelledError:
            pass
