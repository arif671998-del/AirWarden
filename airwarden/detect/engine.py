"""Detection engine: runs every rule detector over a capture and returns the
combined, de-duplicated list of DetectionEvents.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from ..schema import Frame, DetectionEvent, AttackType
from . import (deauth, eviltwin, rogue, karma, beacon_flood, auth_flood,
               typosquat, mac_spoof)


@dataclass
class DetectorConfig:
    # deauth flood
    deauth_window_s: float = 10.0
    deauth_threshold: int = 20
    deauth_high_rate: float = 10.0
    # karma
    karma_min_ssids: int = 4
    # beacon flood
    beacon_window_s: float = 8.0
    beacon_flood_threshold: int = 15
    # auth/assoc flood
    auth_window_s: float = 10.0
    auth_flood_threshold: int = 25
    # mac spoof (sequence-number analysis)
    spoof_min_frames: int = 6
    spoof_min_gap: int = 100
    spoof_min_regressions: int = 3


class DetectionEngine:
    def __init__(self, baseline, config: DetectorConfig = None):
        self.baseline = baseline
        self.cfg = config or DetectorConfig()
        self.detectors = [
            ("deauth", deauth.detect),
            ("eviltwin", eviltwin.detect),
            ("typosquat", typosquat.detect),
            ("rogue", rogue.detect),
            ("karma", karma.detect),
            ("beacon_flood", beacon_flood.detect),
            ("auth_flood", auth_flood.detect),
            ("mac_spoof", mac_spoof.detect),
        ]

    def run(self, frames: List[Frame]) -> List[DetectionEvent]:
        indexed = list(enumerate(frames))
        events: List[DetectionEvent] = []
        for _name, fn in self.detectors:
            events.extend(fn(indexed, self.baseline, self.cfg))
        events = self._dedupe(events)
        events.sort(key=lambda e: (e.ts, e.attack.value))
        return events

    def _dedupe(self, events: List[DetectionEvent]) -> List[DetectionEvent]:
        # if a BSSID is already called an evil twin or typosquat, the generic
        # rogue-AP finding for the same BSSID is redundant — drop it.
        specific = {e.bssid for e in events
                    if e.attack in (AttackType.EVIL_TWIN, AttackType.SSID_TYPOSQUAT)}
        return [e for e in events
                if not (e.attack == AttackType.ROGUE_AP and e.bssid in specific)]
