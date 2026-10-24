"""Replay recorded pcaps as Frame objects (dependency-free)."""
from __future__ import annotations

import time
from typing import Iterator, List

from ..schema import Frame
from .. import pcap


def replay_pcap(path: str) -> List[Frame]:
    """Read every frame from a pcap at once."""
    return pcap.read_pcap(path)


def iter_pcap(path: str, realtime: bool = False, speed: float = 1.0) -> Iterator[Frame]:
    """Yield frames one at a time; with realtime=True, sleep between frames to
    reproduce the original timing (useful for a live-looking demo feed)."""
    frames = pcap.read_pcap(path)
    prev = None
    for f in frames:
        if realtime and prev is not None:
            dt = (f.ts - prev) / max(speed, 0.001)
            if dt > 0:
                time.sleep(min(dt, 2.0))
        prev = f.ts
        yield f
