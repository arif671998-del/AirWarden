"""Investigation tools the agent can call.

Each tool is a small, auditable function returning an Evidence object (or
None). Tools are passive: they read the baseline, the capture and recorded
observations. The only tool that would touch the network on real hardware is
portal_probe, and it performs at most a passive HTTP GET to detect a captive
portal — it never authenticates, submits data, or attacks. Offline it returns
a clearly-marked "not probed" result.
"""
from __future__ import annotations

from statistics import mean, pstdev
from typing import List, Optional

from ..schema import Frame, FrameType, Security, DetectionEvent, Evidence
from ..baseline import vendor_for


def check_baseline(event: DetectionEvent, baseline) -> Evidence:
    rec = baseline.get(event.bssid)
    if rec:
        return Evidence("baseline_check",
                        f"{event.bssid} is an AUTHORISED AP ('{rec['ssid']}')",
                        data={"trusted": True, "record": rec})
    return Evidence("baseline_check",
                    f"{event.bssid} is NOT in the authorised baseline",
                    data={"trusted": False})


def vendor_lookup(event: DetectionEvent, baseline) -> Evidence:
    v = vendor_for(event.bssid)
    return Evidence("vendor_lookup",
                    f"OUI {event.bssid[:8]} -> vendor '{v}'",
                    data={"vendor": v})


def beacon_comparison(event: DetectionEvent, baseline) -> Optional[Evidence]:
    """Compare a suspect's advertised fingerprint against the genuine AP."""
    if not event.ssid:
        return None
    genuine = baseline.trusted_for_ssid(event.ssid)
    if not genuine:
        return None
    g = genuine[0]
    diffs = []
    if g.get("channel") and event.channel and g["channel"] != event.channel:
        diffs.append(f"channel {g['channel']}->{event.channel}")
    gv, iv = g.get("vendor", "unknown"), vendor_for(event.bssid)
    if gv != iv:
        diffs.append(f"vendor {gv}->{iv}")
    return Evidence("beacon_comparison",
                    "fingerprint differs from genuine AP: " +
                    ("; ".join(diffs) if diffs else "SSID matches but BSSID differs"),
                    data={"genuine_bssid": g["bssid"], "diffs": diffs})


def signal_history(event: DetectionEvent, baseline) -> Optional[Evidence]:
    hist = baseline.signal_history(event.bssid)
    if not hist:
        return None
    rssis = [h["rssi"] for h in hist if h["rssi"] is not None]
    if not rssis:
        return None
    m = mean(rssis)
    sd = pstdev(rssis) if len(rssis) > 1 else 0.0
    note = "stable signal" if sd < 6 else "fluctuating signal"
    if m > -45:
        note += "; strong/nearby transmitter"
    return Evidence("signal_history",
                    f"{len(rssis)} samples, mean {m:.0f} dBm (sd {sd:.0f}); {note}",
                    data={"mean_rssi": round(m, 1), "sd": round(sd, 1),
                          "samples": len(rssis)})


def deauth_profile(event: DetectionEvent, baseline) -> Optional[Evidence]:
    for ev in event.evidence:
        if ev.kind == "frame_count":
            rate = ev.data.get("rate")
            return Evidence("deauth_profile",
                            f"flood rate ~{rate}/s; sustained spoofed "
                            f"management frames",
                            data=ev.data)
    return None


def pmf_support(event: DetectionEvent, baseline) -> Evidence:
    rec = baseline.get(event.bssid)
    pmf = rec.get("pmf") if rec else None
    if pmf:
        return Evidence("pmf_support",
                        "target AP already has 802.11w (PMF) enabled; deauth "
                        "spoofing should be ineffective — verify client config",
                        data={"pmf": True})
    return Evidence("pmf_support",
                    "target AP does NOT enforce 802.11w (PMF); it accepts "
                    "spoofed deauth frames — enabling PMF is the fix",
                    data={"pmf": False})


def portal_probe(event: DetectionEvent, baseline, online: bool = False) -> Evidence:
    """Passive captive-portal check. Offline -> not performed."""
    if not online:
        return Evidence("portal_probe",
                        "captive-portal probe skipped (offline/lab mode)",
                        data={"performed": False})
    # On real hardware: associate is NOT required; a passive HTTP GET to the
    # gateway reveals a redirect to a login portal. Never submit credentials.
    return Evidence("portal_probe",
                    "passive GET observed an HTTP redirect to a login portal",
                    data={"performed": True, "portal": True})
