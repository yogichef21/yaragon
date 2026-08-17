"""Pytest configuration: make the src/ package importable and provide helpers."""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import pytest
from scapy.layers.l2 import Ether


@pytest.fixture
def parser():
    from yaragon.analysis.packet_parser import PacketParser
    return PacketParser()


def build(pkt):
    """Serialise + re-parse a scapy packet so its fields are populated exactly
    like a frame captured off the wire (real captures are always 'built')."""
    return Ether(bytes(pkt))
