"""Central logging setup for Yaragon.

Logs go to both stderr and a rotating file under the data dir. The logger name
is always prefixed with "yaragon" so branding stays consistent in the logs.
"""
from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler

from .config import data_dir

_CONFIGURED = False


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    global _CONFIGURED
    root = logging.getLogger("yaragon")
    if _CONFIGURED:
        return root

    root.setLevel(level)
    fmt = logging.Formatter(
        "%(asctime)s [Yaragon] %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    root.addHandler(stream)

    try:
        logfile = data_dir() / "yaragon.log"
        fileh = RotatingFileHandler(logfile, maxBytes=2_000_000, backupCount=3)
        fileh.setFormatter(fmt)
        root.addHandler(fileh)
        # Logs can contain captured topology detail; keep them owner-only.
        try:
            os.chmod(logfile, 0o600)
        except OSError:
            pass
    except Exception:
        pass

    root.propagate = False
    _CONFIGURED = True
    return root


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"yaragon.{name}")
