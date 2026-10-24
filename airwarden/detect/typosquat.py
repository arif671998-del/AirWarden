"""SSID typosquatting / homoglyph-twin detector.

A subtler evil twin: instead of copying the trusted SSID exactly, the attacker
uses a look-alike — "CampusWiFi" vs "Campus-WiFi", "CampusWiFl" (l for i), or a
Cyrillic character that renders identically. We flag an unauthorised AP whose
SSID is suspiciously close to a trusted one: equal after normalising separators
and confusable characters, or within a small edit distance.
"""
from __future__ import annotations

from typing import List, Tuple, Optional

from ..schema import (Frame, FrameType, DetectionEvent, AttackType, Severity,
                      Evidence)

# common homoglyph / confusable mappings -> ascii
_CONFUSABLE = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "а": "a", "е": "e", "о": "o", "с": "c", "р": "p", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ԁ": "d", "ո": "n", "ⅼ": "l", "ｗ": "w",
}


def _normalize(s: str) -> str:
    s = s.lower()
    s = "".join(_CONFUSABLE.get(c, c) for c in s)
    return "".join(c for c in s if c.isalnum())  # drop -, _, space


def _edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    la, lb = len(a), len(b)
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[lb]


def detect(indexed: List[Tuple[int, Frame]], baseline, cfg) -> List[DetectionEvent]:
    events: List[DetectionEvent] = []
    trusted = baseline.trusted_aps()
    seen = set()

    for i, f in indexed:
        if f.ftype not in (FrameType.BEACON, FrameType.PROBE_RESP) or not f.ssid:
            continue
        if baseline.is_trusted_bssid(f.bssid) or f.bssid in seen:
            continue
        if baseline.trusted_for_ssid(f.ssid):
            continue  # exact clone -> eviltwin detector
        if len(f.ssid) < 4:
            continue

        match = _best_match(f.ssid, trusted)
        if not match:
            continue
        seen.add(f.bssid)
        genuine_ssid, kind, dist = match
        ev = [Evidence(
            "lookalike_ssid",
            f"'{f.ssid}' from {f.bssid} closely resembles trusted "
            f"'{genuine_ssid}' ({kind})",
            [i], {"impostor_ssid": f.ssid, "genuine_ssid": genuine_ssid,
                  "match": kind, "edit_distance": dist})]
        events.append(DetectionEvent(
            attack=AttackType.SSID_TYPOSQUAT, severity=Severity.HIGH,
            ts=f.ts, bssid=f.bssid, ssid=f.ssid, channel=f.channel,
            summary=f"Typosquat: '{f.ssid}' mimics trusted '{genuine_ssid}'",
            evidence=ev, detector="typosquat"))
    return events


def _best_match(ssid: str, trusted) -> Optional[Tuple[str, str, int]]:
    ns = _normalize(ssid)
    for ap in trusted:
        gen = ap["ssid"]
        if gen == ssid:
            continue
        if _normalize(gen) == ns:
            return gen, "homoglyph/separator", 0
        d = _edit_distance(ssid.lower(), gen.lower())
        if 1 <= d <= 2:
            return gen, f"edit distance {d}", d
    return None
