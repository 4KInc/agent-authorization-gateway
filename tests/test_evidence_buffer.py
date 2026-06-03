"""Tests for the async evidence buffer (hot path optimization)."""

import asyncio
import time

import pytest

from gateway.evidence_buffer import EvidenceBuffer, EvidenceItem


# --- Helpers ---

class MockStore:
    """In-memory mock that records all persist calls."""

    def __init__(self, delay: float = 0.0, fail_after: int | None = None):
        self.receipts: list[tuple[str, dict]] = []
        self.stats: list[tuple[str, dict]] = []
        self.rate_limits: list[tuple[str, dict]] = []
        self._delay = delay
        self._fail_after = fail_after
        self._call_count = 0

    async def save_receipt(self, tenant: str, receipt: dict) -> None:
        self._call_count += 1
        if self._fail_after and self._call_count > self._fail_after:
            raise RuntimeError("simulated Firestore failure")
        if self._delay:
            await asyncio.sleep(self._delay)
        self.receipts.append((tenant, receipt))

    async def save_stats(self, tenant: str, stats: dict) -> None:
        self._call_count += 1
        if self._fail_after and self._call_count > self._fail_after:
            raise RuntimeError("simulated Firestore failure")
        if self._delay:
            await asyncio.sleep(self._delay)
        self.stats.append((tenant, stats))

    async def save_rate_limits(self, tenant: str, counters: dict) -> None:
        self._call_count += 1
        if self._fail_after and self._call_count > self._fail_after:
            raise RuntimeError("simulated Firestore failure")
        if self._delay:
            await asyncio.sleep(self._delay)
        self.rate_limits.append((tenant, counters))


# --- Unit tests ---

class TestEvidenceItem:
    def test_defaults(self):
        item = EvidenceItem(kind="receipt", tenant="t1", payload={"a": 1})
        assert item.kind == "receipt"
        assert item.tenant == "t1"
        assert item.enqueued_at > 0


class TestEvidenceBuffer:
    @pytest.mark.asyncio
    async def test_enqueue_and_flush(self):
        store = MockStore()
        buf = EvidenceBuffer(store=store, flush_interval=10.0)

        buf.enqueue("receipt", "tenant-1", {"receipt_hash": "sha256:abc"})
        buf.enqueue("stats", "tenant-1", {"total_receipts": 5})
        buf.enqueue("rate_limits", "tenant-1", {"key": [1.0]})

        assert buf.pending_count == 3
        assert buf._total_enqueued == 3

        count = await buf.flush()
        assert count == 3
        assert buf.pending_count == 0
        assert buf._total_persisted == 3
        assert len(store.receipts) == 1
        assert len(store.stats) == 1
        assert len(store.rate_limits) == 1

    @pytest.mark.asyncio
    async def test_flush_empty_buffer(self):
        store = MockStore()
        buf = EvidenceBuffer(store=store)
        count = await buf.flush()
        assert count == 0

    @pytest.mark.asyncio
    async def test_flush_handles_errors(self):
        store = MockStore(fail_after=1)
        buf = EvidenceBuffer(store=store)

        buf.enqueue("receipt", "t1", {"ok": True})
        buf.enqueue("receipt", "t1", {"will_fail": True})

        count = await buf.flush()
        assert count == 2  # both attempted
        assert buf._total_persisted == 1
        assert buf._flush_errors == 1

    @pytest.mark.asyncio
    async def test_drain_loop_persists(self):
        store = MockStore()
        buf = EvidenceBuffer(store=store, flush_interval=0.05)
        buf.start()

        buf.enqueue("receipt", "t1", {"r": 1})
        buf.enqueue("stats", "t1", {"s": 1})

        # Wait for drain loop to pick them up
        await asyncio.sleep(0.2)

        assert len(store.receipts) == 1
        assert len(store.stats) == 1
        assert buf.pending_count == 0

        await buf.stop()

    @pytest.mark.asyncio
    async def test_stop_flushes_remaining(self):
        store = MockStore()
        buf = EvidenceBuffer(store=store, flush_interval=60.0)  # long interval
        buf.start()

        buf.enqueue("receipt", "t1", {"r": 1})
        buf.enqueue("receipt", "t1", {"r": 2})
        buf.enqueue("receipt", "t1", {"r": 3})

        # Stop should flush remaining
        await buf.stop()

        assert len(store.receipts) == 3
        assert buf._total_persisted == 3

    @pytest.mark.asyncio
    async def test_stats_reporting(self):
        store = MockStore()
        buf = EvidenceBuffer(store=store)

        buf.enqueue("receipt", "t1", {"r": 1})
        buf.enqueue("receipt", "t1", {"r": 2})

        stats = buf.stats
        assert stats["mode"] == "async"
        assert stats["pending"] == 2
        assert stats["total_enqueued"] == 2
        assert stats["total_persisted"] == 0

        await buf.flush()

        stats = buf.stats
        assert stats["pending"] == 0
        assert stats["total_persisted"] == 2
        assert stats["flush_count"] == 1

    @pytest.mark.asyncio
    async def test_high_throughput_enqueue(self):
        """Enqueue many items quickly, verify all are flushed."""
        store = MockStore()
        buf = EvidenceBuffer(store=store, max_batch_size=50)

        for i in range(200):
            buf.enqueue("receipt", "t1", {"seq": i})

        assert buf.pending_count == 200
        count = await buf.flush()
        assert count == 200
        assert len(store.receipts) == 200
