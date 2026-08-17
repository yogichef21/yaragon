"""Yaragon analysis engine.

Owns the consumer thread that drains the capture queue, parses each frame into
a :class:`PacketRecord`, keeps a bounded in-memory history for the traffic
table and inspector.

Deliberately small: this is a focused MITM analysis tool, not a monitoring platform.
It is Qt-free so it can be unit-tested headlessly.
"""
from __future__ import annotations

import queue
import threading
from collections import deque
from typing import Deque, Dict, List, Optional

from .analysis.conversations import (Conversation, build_conversations,
                                     endpoints)
from .analysis.intel import TargetIntel, build_target_intel
from .analysis.model import PacketRecord
from .analysis.packet_parser import PacketParser
from .utils.logging import get_logger

log = get_logger("engine")


class AnalysisEngine:
    def __init__(self, config):
        self.config = config
        self.parser = PacketParser()

        limit = max(1, int(config.packet_history_limit))
        self.queue: "queue.Queue" = queue.Queue(maxsize=50000)
        self._history: Deque[PacketRecord] = deque(maxlen=limit)
        self._index: Dict[int, PacketRecord] = {}
        # Bounded so a stopped/slow GUI drain can never grow this without limit.
        self._new_batch: Deque[PacketRecord] = deque(maxlen=limit)
        self._batch_lock = threading.Lock()
        self._history_lock = threading.Lock()

        self._counter = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None

    # ---- lifecycle ----------------------------------------------------
    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._consume, name="yaragon-engine",
                                        daemon=True)
        self._thread.start()
        log.info("Analysis engine started")

    def stop(self) -> None:
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        log.info("Analysis engine stopped (processed=%d)", self._counter)

    # ---- producer side ------------------------------------------------
    def enqueue(self, pkt) -> None:
        try:
            self.queue.put_nowait(pkt)
        except queue.Full:
            pass

    # ---- consumer thread ---------------------------------------------
    def _consume(self) -> None:
        while self._running or not self.queue.empty():
            try:
                pkt = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                self._process(pkt)
            except Exception as exc:  # never let one bad frame kill the engine
                log.debug("process error: %s", exc)

    def _process(self, pkt) -> None:
        # Parse first: a malformed frame that raises here is dropped before a
        # number is assigned, so packet numbering never has gaps. The counter is
        # bumped and the record numbered under the history lock so a concurrent
        # clear() (which resets the counter) can never produce a duplicate number.
        # build_tree=False: keep only the cheap summary for the 20k history; the
        # inspector rebuilds the decoded tree on demand from rec.raw for the one
        # packet the operator selects.
        rec = self.parser.parse(pkt, build_tree=False)
        with self._history_lock:
            self._counter += 1
            rec.number = self._counter
            if len(self._history) == self._history.maxlen and self._history:
                self._index.pop(self._history[0].number, None)
            self._history.append(rec)
            self._index[rec.number] = rec

        with self._batch_lock:
            self._new_batch.append(rec)

    # ---- GUI-facing readers ------------------------------------------
    def drain_new(self) -> List[PacketRecord]:
        with self._batch_lock:
            batch = list(self._new_batch)
            self._new_batch.clear()
            return batch

    def get_packet(self, number: int) -> Optional[PacketRecord]:
        with self._history_lock:
            return self._index.get(number)

    def history(self) -> List[PacketRecord]:
        with self._history_lock:
            return list(self._history)

    # ---- investigation queries (over the AUTHORITATIVE history) -------
    # These run over the full bounded history, not the smaller display window,
    # so search / follow / triage can never silently miss a packet the engine
    # still holds. Each takes a consistent snapshot under the lock, then works on
    # it lock-free.
    def conversations(self) -> List[Conversation]:
        """All flows in the resident history, heaviest first (triage order)."""
        return build_conversations(self.history())

    def conversation_packets(self, a: str, b: str) -> List[PacketRecord]:
        """Every resident record whose endpoints are exactly {a, b}, in order."""
        pair = frozenset((a, b))
        return [r for r in self.history()
                if frozenset(endpoints(r)) == pair]

    def target_intel(self, host_ip: str) -> TargetIntel:
        """Per-host rollup of already-parsed metadata over the full history."""
        return build_target_intel(self.history(), host_ip)

    @property
    def total(self) -> int:
        return self._counter

    def clear(self) -> None:
        with self._history_lock:
            self._history.clear()
            self._index.clear()
            self._counter = 0
        with self._batch_lock:
            self._new_batch.clear()

    def load_records(self, records: List[PacketRecord]) -> None:
        """Replace the history with records read from an opened .pcap file.

        Each record keeps the number assigned by the importer. The counter is
        set to the highest resident number so that if a live capture is ever
        continued afterwards its numbering never precedes a record still in
        history (opening an over-limit file keeps only the tail).
        """
        with self._history_lock:
            self._history.clear()
            for rec in records:
                self._history.append(rec)
            # The bounded deque keeps only the most recent maxlen records; build
            # the lookup index from what actually remains so get_packet() can
            # never resolve a record history() has dropped - the same invariant
            # _process() maintains for live capture.
            self._index = {rec.number: rec for rec in self._history}
            self._counter = max((r.number for r in self._history), default=0)
        with self._batch_lock:
            self._new_batch.clear()
