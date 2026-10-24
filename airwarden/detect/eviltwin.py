"""Evil-twin / cloned-SSID detector.

An evil twin broadcasts a trusted network's SSID from an AP the operator never
authorised, usually to lure clients onto a fake login portal. We flag a beacon
or probe-response whose SSID matches a baselined network but whose BSSID is not
authorised. A security downgrade (trusted = WPA2, impostor = open) or a vendor
mismatch raises confidence. PMWANI-branded names get special attention because
DoT standardised them, so an unknown AP using that branding is a red flag.
"""
from __future__ import annotations

from typing import List, Tuple

from ..schema import (Frame, FrameType, Security, DetectionEvent, AttackType,
                      Severity, Evidence)
from ..baseline import vendor_for

PMWANI_MARKERS = ("pmwani", "pm-wani", "pm wani")


def _is_pmwani(ssid: str) -> bool:
    s = (ssid or "").lower()
    return any(m in s for m in PMWANI_MARKERS)


def detect(indexed: List[Tuple[int, Frame]], baseline, cfg) -> List[DetectionEvent]:
    events: List[DetectionEvent] = []
    seen_suspect = set()

    for i, f in indexed:
        if f.ftype not in (FrameType.BEACON, FrameType.PROBE_RESP):
            continue
        if not f.ssid:
            continue
        if baseline.is_trusted_bssid(f.bssid):
            continue

        trusted_matches = baseline.trusted_for_ssid(f.ssid)
        if not trusted_matches:
            continue  # unknown SSID -> rogue detector's job, not evil twin
        if f.bssid in seen_suspect:
            continue
        seen_suspect.add(f.bssid)

        genuine = trusted_matches[0]
        ev = [Evidence(
            "ssid_clone",
            f"SSID '{f.ssid}' is broadcast by unauthorised BSSID {f.bssid}; "
            f"authorised BSSID for this SSID is {genuine['bssid']}",
            [i], {"ssid": f.ssid, "impostor": f.bssid,
                  "genuine": genuine["bssid"]})]
        confidence_boost = 0
        # security downgrade
        gen_sec = genuine.get("security")
        if gen_sec in ("wpa2", "wpa3") and f.security == Security.OPEN:
            ev.append(Evidence("security_downgrade",
                               f"authorised network is {gen_sec.upper()} but "
                               f"impostor is OPEN (fake portal pattern)",
                               [i], {"genuine": gen_sec, "impostor": "open"}))
            confidence_boost += 2
        # vendor mismatch
        gv, iv = genuine.get("vendor", "unknown"), vendor_for(f.bssid)
        if gv != "unknown" and iv != "unknown" and gv != iv:
            ev.append(Evidence("vendor_mismatch",
                               f"authorised AP vendor {gv}, impostor {iv}",
                               [i], {"genuine": gv, "impostor": iv}))
            confidence_boost += 1
        # channel difference
        if genuine.get("channel") and f.channel and genuine["channel"] != f.channel:
            ev.append(Evidence("channel_shift",
                               f"authorised on ch{genuine['channel']}, "
                               f"impostor on ch{f.channel}",
                               [i], {}))
            confidence_boost += 1
        if _is_pmwani(f.ssid):
            ev.append(Evidence("pmwani_branding",
                               "SSID uses PMWANI branding from an unauthorised AP",
                               [i], {}))
            confidence_boost += 2

        sev = Severity.HIGH if confidence_boost >= 2 else Severity.MEDIUM
        events.append(DetectionEvent(
            attack=AttackType.EVIL_TWIN, severity=sev, ts=f.ts,
            bssid=f.bssid, ssid=f.ssid, channel=f.channel,
            summary=f"Evil twin: '{f.ssid}' cloned by {f.bssid}",
            evidence=ev, detector="eviltwin"))
    return events
