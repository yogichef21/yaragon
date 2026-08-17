"""CaptureWorker logic tests.

The live sniffer (AsyncSniffer) needs a real NIC and cannot run here, but the
worker's pure control logic - pause gating, pps throttling, bounded-queue drop
accounting and pause/resume state - is exercisable directly by driving
``_on_packet``/``_throttled`` with placeholder frames.
"""
import queue

from yaragon.network.capture import CaptureWorker


def test_bounded_queue_drops_when_full():
    """When the queue is full, extra frames are dropped and counted, never
    raised - a slow consumer can't crash or unbound the capture path."""
    q = queue.Queue(maxsize=3)
    w = CaptureWorker("lo", q)
    for _ in range(5):
        w._on_packet(object())          # placeholder frames
    assert q.qsize() == 3
    assert w.captured == 3
    assert w.dropped == 2


def test_pause_gates_delivery_then_resume_restores_it():
    q = queue.Queue(maxsize=10)
    w = CaptureWorker("lo", q)
    w.pause()
    assert w.is_paused is True
    w._on_packet(object())
    assert w.captured == 0 and q.qsize() == 0   # dropped silently while paused
    w.resume()
    assert w.is_paused is False
    w._on_packet(object())
    assert w.captured == 1 and q.qsize() == 1


def test_pps_throttle_caps_delivery_per_window():
    """With max_pps=2 the first two frames in a 1s window pass, the rest are
    throttled (returns True) without touching the queue."""
    w = CaptureWorker("lo", queue.Queue(maxsize=100), max_pps=2)
    verdicts = [w._throttled() for _ in range(5)]
    assert verdicts == [False, False, True, True, True]


def test_no_throttle_when_pps_zero():
    w = CaptureWorker("lo", queue.Queue(maxsize=100), max_pps=0)
    assert all(w._throttled() is False for _ in range(100))


def test_empty_bpf_filter_normalises_to_none():
    """An empty BPF string must become None so scapy captures everything rather
    than being handed an empty filter expression."""
    assert CaptureWorker("lo", queue.Queue(), "").bpf_filter is None
    assert CaptureWorker("lo", queue.Queue(), "tcp port 80").bpf_filter == "tcp port 80"
