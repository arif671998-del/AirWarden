"""MAC / BSSID impersonation detector via sequence-number analysis.

Every 802.11 frame carries a sequence number that an AP increments by one per
frame (wrapping at 4096). If two radios transmit under the *same* BSSID — a
spoofer alongside the genuine AP — the captured sequence numbers from that
BSSID no longer rise smoothly: you see large backward jumps, as two independent
counters interleave. We flag a BSSID whose sequence stream shows repeated
non-wraparound regressions.
"""
from __future__ import annotations

from typing import List, Tuple

from ..schema import Frame, FrameType, DetectionEvent, AttackType, Severity, Evidence

_MGMT = (FrameType.BEACON, FrameType.PROBE_RESP)


def detect(indexed: List[Tuple[int, Frame]], baseline, cfg) -> List[DetectionEvent]:
    events: List[DetectionEvent] = []
    by_bssid = {}
    for i, f in indexed:
        if f.ftype in _MGMT and f.seq is not None:
            by_bssid.setdefault(f.bssid, []).append((i, f))

    for bssid, items in by_bssid.items():
        if len(items) < cfg.spoof_min_frames:
            continue
        items.sort(key=lambda x: x[1].ts)
        regressions = []
        for (pi, pf), (ci, cf) in zip(items, items[1:]):
            delta = cf.seq - pf.seq
            # ignore forward progress and legitimate wraparound (near 4095 -> 0)
            if delta < 0 and not (pf.seq > 3800 and cf.seq < 300):
                if abs(delta) > cfg.spoof_min_gap:
                    regressions.append((ci, pf.seq, cf.seq))
        if len(regressions) < cfg.spoof_min_regressions:
            continue
        refs = [ci for ci, _, _ in regressions][:20]
        examples = "; ".join(f"{a}->{b}" for _, a, b in regressions[:4])
        sev = Severity.HIGH if baseline.is_trusted_bssid(bssid) else Severity.MEDIUM
        ev = [
            Evidence("seqnum_regression",
                     f"{len(regressions)} large sequence-number regressions on "
                     f"{bssid} (e.g. {examples}) — two counters under one BSSID",
                     refs, {"regressions": len(regressions)}),
            Evidence("impersonation",
                     "a single genuine AP increments sequence numbers smoothly; "
                     "interleaved counters indicate a second radio spoofing this BSSID",
                     []),
        ]
        events.append(DetectionEvent(
            attack=AttackType.MAC_SPOOF, severity=sev, ts=items[0][1].ts,
            bssid=bssid, ssid=items[0][1].ssid,
            summary=f"MAC spoofing: two radios sharing BSSID {bssid}",
            evidence=ev, detector="mac_spoof"))
    return events
