"""Export captured packets to (and import them from) a standard .pcap file.

Rebuilds each frame from the raw bytes kept on the :class:`PacketRecord`
(``rec.raw``) and writes them with scapy's ``wrpcap`` so the result opens
cleanly in Wireshark, tcpdump and any other pcap reader. The original capture
timestamp is preserved on each frame. Only records that actually carry raw
bytes are written; nothing is fabricated.

:func:`import_pcap` is the reverse: it reads a saved .pcap and runs every frame
through the same :class:`PacketParser` used for live capture, so an opened file
flows through the inspector and export path exactly like a live capture would.
"""
from __future__ import annotations

from typing import Iterable, List

from ..analysis.model import PacketRecord
from ..utils.logging import get_logger

log = get_logger("exporter")


def export_pcap(records: Iterable[PacketRecord], out_path: str) -> int:
    """Write *records* to *out_path* as pcap. Returns the number of frames written."""
    from scapy.all import Ether, wrpcap

    frames = []
    for rec in records:
        if not rec.raw:
            continue
        frame = Ether(rec.raw)
        # Always pin the capture time (even 0.0) so scapy never substitutes the
        # current time for a frame whose original timestamp was unavailable.
        frame.time = rec.timestamp
        frames.append(frame)

    wrpcap(out_path, frames)
    log.info("Exported %d packet(s) to %s", len(frames), out_path)
    return len(frames)


def import_pcap(path: str, max_frames: int = 20000) -> List[PacketRecord]:
    """Read *path* and dissect every frame into a :class:`PacketRecord`.

    The file is read with a *streaming* reader and capped at *max_frames* so a
    large or maliciously-inflated .pcap can never materialise every frame at once
    and OOM-kill the app - the engine's history is bounded anyway, so frames past
    the cap could not be shown or exported. Records are numbered sequentially
    1..N and each frame's pcap capture time is preserved.
    """
    from scapy.utils import PcapReader

    from ..analysis.packet_parser import PacketParser

    parser = PacketParser()
    records: List[PacketRecord] = []
    skipped = 0
    truncated = False
    with PcapReader(path) as reader:
        for frame in reader:
            if len(records) >= max_frames:
                truncated = True
                break
            # One unparseable frame must not abort the whole open - mirror the
            # live engine, which drops a bad frame and keeps going. Numbering
            # stays gap-free over the frames that did parse.
            try:
                rec = parser.parse(frame)
                rec.number = len(records) + 1
                try:
                    rec.timestamp = float(frame.time)
                except Exception:
                    pass
                records.append(rec)
            except Exception as exc:
                skipped += 1
                log.debug("skipping unparseable frame in %s: %s", path, exc)
    if truncated:
        log.warning("Imported the first %d packet(s) from %s (file exceeds the "
                    "%d-frame cap; remaining frames not loaded)",
                    len(records), path, max_frames)
    elif skipped:
        log.warning("Imported %d packet(s) from %s (%d unparseable frame(s) skipped)",
                    len(records), path, skipped)
    else:
        log.info("Imported %d packet(s) from %s", len(records), path)
    return records
