"""Deauthentication / disassociation flood detector.

Networks without 802.11w (Protected Management Frames) accept spoofed deauth
frames, so an attacker can knock clients off repeatedly. We flag an abnormal
burst of deauth/disassoc frames within a sliding time window.
"""
from __future__ import annotations

from typing import List, Tuple

from ..schema import Frame, FrameType, DetectionEvent, AttackType, Severity, Evidence


def detect(indexed: List[Tuple[int, Frame]], baseline, cfg) -> List[DetectionEvent]:
    events: List[DetectionEvent] = []
    deauths = [(i, f) for i, f in indexed
               if f.ftype in (FrameType.DEAUTH, FrameType.DISASSOC)]
    if not deauths:
        return events

    # group by targeted link (bssid) and slide a window over timestamps
    by_bssid = {}
    for i, f in deauths:
        by_bssid.setdefault(f.bssid, []).append((i, f))

    for bssid, items in by_bssid.items():
        items.sort(key=lambda x: x[1].ts)
        best_window = []
        for start in range(len(items)):
            t0 = items[start][1].ts
            window = [it for it in items[start:]
                      if it[1].ts - t0 <= cfg.deauth_window_s]
            if len(window) > len(best_window):
                best_window = window
        count = len(best_window)
        if count < cfg.deauth_threshold:
            continue
        span = max(0.001, best_window[-1][1].ts - best_window[0][1].ts)
        rate = count / span
        refs = [i for i, _ in best_window]
        reasons = sorted({f.reason for _, f in best_window if f.reason is not None})
        trusted = baseline.is_trusted_bssid(bssid)
        sev = Severity.HIGH if (trusted and rate >= cfg.deauth_high_rate) else Severity.MEDIUM
        ev = [
            Evidence("frame_count",
                     f"{count} deauth/disassoc frames in {span:.1f}s "
                     f"(~{rate:.0f}/s) targeting {bssid}",
                     refs, {"count": count, "rate": round(rate, 1)}),
            Evidence("reason_codes",
                     f"reason codes observed: {reasons or 'n/a'}",
                     [], {"reasons": reasons}),
        ]
        if trusted:
            ev.append(Evidence("targets_trusted_ap",
                               f"{bssid} is an authorised AP in the baseline",
                               [], {"bssid": bssid}))
        events.append(DetectionEvent(
            attack=AttackType.DEAUTH_FLOOD, severity=sev,
            ts=best_window[0][1].ts, bssid=bssid,
            summary=f"Deauth flood: {count} frames (~{rate:.0f}/s) against {bssid}",
            evidence=ev, detector="deauth"))
    return events
