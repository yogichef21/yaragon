"""Background packet capture worker.

Runs entirely outside the GUI thread. Uses scapy's AsyncSniffer and pushes raw
frames onto a bounded, thread-safe queue as fast as possible; the heavy parsing
happens in the analysis engine's consumer thread. This split keeps the sniffer
lightweight (so it drops fewer packets) and guarantees the GUI never blocks.

Features required by the spec:
  * background capture (own thread)
  * thread-safe bounded queue (bounded memory)
  * optional pause
  * optional pps throttle
  * optional BPF pre-filter
  * graceful stop
"""
from __future__ import annotations

import queue
import threading
import time

from ..utils.logging import get_logger

log = get_logger("capture")


class CaptureWorker:
    def __init__(self, iface: str, pkt_queue: "queue.Queue",
                 bpf_filter: str = "", max_pps: int = 0):
        self.iface = iface
        self.queue = pkt_queue
        self.bpf_filter = bpf_filter or None
        self.max_pps = max_pps
        self._sniffer = None
        self._paused = threading.Event()
        self._running = False
        self.dropped = 0
        self.captured = 0
        self._window_start = time.time()
        self._window_count = 0

    # -- lifecycle ------------------------------------------------------
    def start(self) -> None:
        from scapy.all import AsyncSniffer

        self._running = True
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            prn=self._on_packet,
            filter=self.bpf_filter,
            store=False,
        )
        self._sniffer.start()
        log.info("Capture started on %s (filter=%s)", self.iface, self.bpf_filter)

    def stop(self) -> None:
        self._running = False
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as exc:
                log.debug("sniffer stop: %s", exc)
            self._sniffer = None
        log.info("Capture stopped on %s (captured=%d dropped=%d)",
                 self.iface, self.captured, self.dropped)

    def pause(self) -> None:
        self._paused.set()

    def resume(self) -> None:
        self._paused.clear()

    @property
    def is_paused(self) -> bool:
        return self._paused.is_set()

    # -- internal -------------------------------------------------------
    def _throttled(self) -> bool:
        if self.max_pps <= 0:
            return False
        now = time.time()
        if now - self._window_start >= 1.0:
            self._window_start = now
            self._window_count = 0
        if self._window_count >= self.max_pps:
            return True
        self._window_count += 1
        return False

    def _on_packet(self, pkt) -> None:
        if self._paused.is_set():
            return
        if self._throttled():
            return
        try:
            self.queue.put_nowait(pkt)
            self.captured += 1
        except queue.Full:
            self.dropped += 1
