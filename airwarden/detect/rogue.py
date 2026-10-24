"""Rogue / unknown AP detector.

Any AP that beacons an SSID not present in the baseline and whose BSSID is not
authorised is a rogue-AP candidate. This is distinct from an evil twin (which
clones a *trusted* SSID); a rogue AP introduces a new network. An unknown AP
using PMWANI branding is escalated, since those names are standardised.
"""
from __future__ import annotations

from typing import List, Tuple

from ..schema import (Frame, FrameType, DetectionEvent, AttackType, Severity,
                      Evidence, Security)
from ..baseline import vendor_for
from .eviltwin import _is_pmwani


def detect(indexed: List[Tuple[int, Frame]], baseline, cfg) -> List[DetectionEvent]:
    events: List[DetectionEvent] = []
    reported = set()

    for i, f in indexed:
        if f.ftype != FrameType.BEACON or not f.ssid:
            continue
        if baseline.is_trusted_bssid(f.bssid):
            continue
        if baseline.trusted_for_ssid(f.ssid):
            continue  # clones a trusted SSID -> handled by eviltwin
        if f.bssid in reported:
            continue
        reported.add(f.bssid)

        ev = [Evidence("unknown_ap",
                       f"AP {f.bssid} broadcasting '{f.ssid}' (ch{f.channel}, "
                       f"{f.security.value}) is not in the baseline",
                       [i], {"bssid": f.bssid, "ssid": f.ssid,
                             "vendor": vendor_for(f.bssid)})]
        sev = Severity.LOW
        if _is_pmwani(f.ssid):
            ev.append(Evidence("pmwani_branding",
                               "unauthorised AP uses PMWANI branding",
                               [i], {}))
            sev = Severity.HIGH
        elif f.security == Security.OPEN:
            ev.append(Evidence("open_network",
                               "open network invites opportunistic clients",
                               [i], {}))
            sev = Severity.MEDIUM
        events.append(DetectionEvent(
            attack=AttackType.ROGUE_AP, severity=sev, ts=f.ts,
            bssid=f.bssid, ssid=f.ssid, channel=f.channel,
            summary=f"Rogue AP: unknown network '{f.ssid}' from {f.bssid}",
            evidence=ev, detector="rogue"))
    return events
