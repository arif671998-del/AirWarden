"""Authentication / association flood detector.

An attacker fires many authentication or association requests at an AP, often
from spoofed/random client MACs, to exhaust its association table and deny
service. The tell: a burst of auth/assoc-request frames to one BSSID from an
unusually large number of distinct source addresses in a short window.
"""
from __future__ import annotations

from typing import List, Tuple

from ..schema import Frame, FrameType, DetectionEvent, AttackType, Severity, Evidence

_FLOOD_TYPES = (FrameType.AUTH, FrameType.ASSOC_REQ)


def detect(indexed: List[Tuple[int, Frame]], baseline, cfg) -> List[DetectionEvent]:
    events: List[DetectionEvent] = []
    by_bssid = {}
    for i, f in indexed:
        if f.ftype in _FLOOD_TYPES:
            by_bssid.setdefault(f.addr3 or f.addr1, []).append((i, f))

    for bssid, items in by_bssid.items():
        items.sort(key=lambda x: x[1].ts)
        best = []
        for start in range(len(items)):
            t0 = items[start][1].ts
            window = [it for it in items[start:]
                      if it[1].ts - t0 <= cfg.auth_window_s]
            if len(window) > len(best):
                best = window
        if len(best) < cfg.auth_flood_threshold:
            continue
        clients = {f.addr2 for _, f in best}
        span = max(0.001, best[-1][1].ts - best[0][1].ts)
        refs = [i for i, _ in best][:50]
        trusted = baseline.is_trusted_bssid(bssid)
        ev = [
            Evidence("request_burst",
                     f"{len(best)} auth/assoc requests to {bssid} in {span:.1f}s "
                     f"from {len(clients)} distinct source MACs",
                     refs, {"count": len(best), "clients": len(clients)}),
        ]
        if len(clients) > cfg.auth_flood_threshold // 2:
            ev.append(Evidence("mac_randomisation",
                               "many unique source MACs suggests spoofed clients",
                               [], {"clients": len(clients)}))
        if trusted:
            ev.append(Evidence("targets_trusted_ap",
                               f"{bssid} is an authorised AP", [], {}))
        events.append(DetectionEvent(
            attack=AttackType.AUTH_FLOOD,
            severity=Severity.HIGH if trusted else Severity.MEDIUM,
            ts=best[0][1].ts, bssid=bssid,
            summary=f"Auth/assoc flood: {len(best)} requests at {bssid}",
            evidence=ev, detector="auth_flood"))
    return events
