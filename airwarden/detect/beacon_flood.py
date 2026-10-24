"""Beacon flood detector.

Tools like mdk4 beacon mode spray hundreds of fake networks to drown out the
real ones and confuse clients. The tell: a sudden surge in the number of
*distinct* access points (BSSIDs) seen beaconing within a short window, far
above the handful a normal environment shows.
"""
from __future__ import annotations

from typing import List, Tuple

from ..schema import Frame, FrameType, DetectionEvent, AttackType, Severity, Evidence


def detect(indexed: List[Tuple[int, Frame]], baseline, cfg) -> List[DetectionEvent]:
    beacons = [(i, f) for i, f in indexed if f.ftype == FrameType.BEACON]
    if not beacons:
        return []

    best = []  # list of (i,f) in the densest window
    for start in range(len(beacons)):
        t0 = beacons[start][1].ts
        window = [it for it in beacons[start:]
                  if it[1].ts - t0 <= cfg.beacon_window_s]
        if len({f.bssid for _, f in window}) > len({f.bssid for _, f in best}):
            best = window
    distinct = {f.bssid for _, f in best}
    unknown = {b for b in distinct if not baseline.is_trusted_bssid(b)}
    if len(unknown) < cfg.beacon_flood_threshold:
        return []

    span = max(0.001, best[-1][1].ts - best[0][1].ts)
    refs = [i for i, f in best if f.bssid in unknown][:50]
    sample = list({f.ssid for _, f in best if f.bssid in unknown and f.ssid})[:6]
    ev = [
        Evidence("ap_surge",
                 f"{len(unknown)} distinct unknown APs beaconing in {span:.1f}s "
                 f"(normal is a handful)", refs,
                 {"distinct_unknown": len(unknown), "span_s": round(span, 1)}),
        Evidence("ssid_sample", f"sample SSIDs: {', '.join(sample)}", [],
                 {"ssids": sample}),
    ]
    return [DetectionEvent(
        attack=AttackType.BEACON_FLOOD, severity=Severity.HIGH,
        ts=best[0][1].ts, bssid="(many)",
        summary=f"Beacon flood: {len(unknown)} fake APs in {span:.1f}s",
        evidence=ev, detector="beacon_flood")]
