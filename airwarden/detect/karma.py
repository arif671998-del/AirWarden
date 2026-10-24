"""Karma / MANA attack detector.

A Karma AP answers *every* probe request, pretending to be whatever saved
network a client is looking for. The tell: a single BSSID sends probe-responses
advertising many different SSIDs — a legitimate AP only ever answers for its
own. We flag a BSSID that responds for more than a few distinct SSIDs.
"""
from __future__ import annotations

from typing import List, Tuple

from ..schema import Frame, FrameType, DetectionEvent, AttackType, Severity, Evidence


def detect(indexed: List[Tuple[int, Frame]], baseline, cfg) -> List[DetectionEvent]:
    events: List[DetectionEvent] = []
    by_bssid = {}  # bssid -> {ssid: first_index}
    for i, f in indexed:
        if f.ftype != FrameType.PROBE_RESP or not f.ssid:
            continue
        by_bssid.setdefault(f.bssid, {}).setdefault(f.ssid, i)

    for bssid, ssids in by_bssid.items():
        if baseline.is_trusted_bssid(bssid):
            continue
        if len(ssids) < cfg.karma_min_ssids:
            continue
        refs = list(ssids.values())
        names = list(ssids.keys())
        sev = Severity.HIGH if len(ssids) >= cfg.karma_min_ssids + 2 else Severity.MEDIUM
        ev = [
            Evidence("many_ssids_one_ap",
                     f"{bssid} answered probes for {len(ssids)} different SSIDs: "
                     f"{', '.join(names[:6])}" + (" …" if len(names) > 6 else ""),
                     refs, {"ssid_count": len(ssids), "ssids": names}),
            Evidence("karma_pattern",
                     "a genuine AP answers only for its own SSID; answering for "
                     "many indicates a Karma/MANA rogue impersonating saved networks",
                     []),
        ]
        events.append(DetectionEvent(
            attack=AttackType.KARMA_PROBE, severity=sev,
            ts=indexed[refs[0]][1].ts, bssid=bssid,
            summary=f"Karma attack: {bssid} impersonates {len(ssids)} networks",
            evidence=ev, detector="karma"))
    return events
