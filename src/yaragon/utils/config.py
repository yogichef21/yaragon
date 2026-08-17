"""Configuration management for Yaragon.

Settings are persisted as JSON under ~/.config/yaragon/config.json (mode 0600)
so a small amount of state - notably the last-used interface - survives
restarts. Nothing here is hardcoded to a specific lab; values are discovered at
runtime and only *remembered* here once the user chooses them.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

APP_DIRNAME = "yaragon"


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    d = Path(base) / APP_DIRNAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def data_dir() -> Path:
    # Still used by logging.py for the rotating log-file location (unrelated to
    # the removed SQLite store).
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share"
    )
    d = Path(base) / APP_DIRNAME
    d.mkdir(parents=True, exist_ok=True)
    return d


@dataclass
class Config:
    """User-tunable settings with sensible, lab-safe defaults."""

    # Capture / performance
    interface: str = ""
    packet_history_limit: int = 20000          # bounded memory buffer; the packet
                                               # table mirrors this exactly so a
                                               # display filter never misses a
                                               # packet the engine still holds
    gui_flush_interval_ms: int = 400           # GUI update batching cadence
    capture_bpf_filter: str = ""               # optional BPF pre-filter
    max_capture_pps: int = 0                   # 0 = unlimited; else throttle

    # MITM
    arp_reassert_interval: float = 2.0         # seconds between ARP refreshes
    manage_ip_forwarding: bool = True          # app toggles net.ipv4.ip_forward

    @classmethod
    def load(cls) -> "Config":
        path = config_dir() / "config.json"
        if path.exists():
            try:
                data = json.loads(path.read_text())
                known = {f for f in cls().__dict__}
                clean = {k: v for k, v in data.items() if k in known}
                return cls(**clean)
            except Exception:
                # Corrupt config should never crash the app.
                return cls()
        return cls()

    def save(self) -> None:
        path = config_dir() / "config.json"
        try:
            path.write_text(json.dumps(asdict(self), indent=2))
            # Config can name the local topology (interface); keep it readable
            # only by the owner on a shared host.
            os.chmod(path, 0o600)
        except Exception:
            pass
