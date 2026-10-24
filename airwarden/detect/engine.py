"""Detection engine: runs every rule detector over a capture and returns the
combined, de-duplicated list of DetectionEvents.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from ..schema import Frame, DetectionEvent
from . import deauth, eviltwin, rogue


@dataclass
class DetectorConfig:
    deauth_window_s: float = 10.0     # sliding window for flood detection
    deauth_threshold: int = 20        # frames in window to raise an event
    deauth_high_rate: float = 10.0    # frames/s that makes it HIGH severity


class DetectionEngine:
    def __init__(self, baseline, config: DetectorConfig = None):
        self.baseline = baseline
        self.cfg = config or DetectorConfig()
        self.detectors = [
            ("deauth", deauth.detect),
            ("eviltwin", eviltwin.detect),
            ("rogue", rogue.detect),
        ]

    def run(self, frames: List[Frame]) -> List[DetectionEvent]:
        indexed = list(enumerate(frames))
        events: List[DetectionEvent] = []
        for _name, fn in self.detectors:
            events.extend(fn(indexed, self.baseline, self.cfg))
        events.sort(key=lambda e: (e.ts, e.attack.value))
        return events
