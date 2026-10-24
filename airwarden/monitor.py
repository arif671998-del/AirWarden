"""Live monitoring loop: capture -> detect -> investigate, continuously.

Runs on a monitor-mode interface (e.g. an Alfa adapter on Kali). It is
PASSIVE: it only listens and never transmits a frame. Periodically it runs the
detection engine over a rolling window of captured frames and investigates any
new events, printing evidence-backed verdicts (and pushing Telegram alerts when
configured).

Usage (as root, on a monitor-mode iface):
    sudo airmon-ng start wlan0                 # -> wlan0mon
    sudo python3 -m airwarden monitor wlan0mon --learn-seconds 20 --channels 1,6,11

Build the baseline during a window you KNOW is clean (your own network only),
then let it run. Every unknown AP around you is then flagged live.
"""
from __future__ import annotations

import os
import time
from collections import deque
from typing import List, Optional

from .schema import Frame
from .baseline import Baseline
from .detect import DetectionEngine
from .agent import Investigator
from .alert import telegram
from .capture.live import _to_frame

_MARK = {"confirmed": "[!]", "suspected": "[?]", "needs_review": "[.]", "benign": "[ ]"}


def _set_channel(iface: str, ch: int) -> None:
    os.system(f"iw dev {iface} set channel {ch} >/dev/null 2>&1")


def _collect(iface: str, seconds: float) -> List[Frame]:
    from scapy.sendrecv import sniff
    pkts = sniff(iface=iface, timeout=seconds, store=True)
    out = []
    for p in pkts:
        fr = _to_frame(p)
        if fr:
            out.append(fr)
    return out


def _sweep(iface: str, seconds: float, channels: Optional[List[int]]) -> List[Frame]:
    if not channels:
        return _collect(iface, seconds)
    per = max(0.5, seconds / len(channels))
    frames: List[Frame] = []
    for ch in channels:
        _set_channel(iface, ch)
        frames += _collect(iface, per)
    return frames


def run_monitor(iface: str, baseline: Baseline, learn_seconds: int = 20,
                interval: float = 6, window: float = 60,
                channels: Optional[List[int]] = None, online: bool = False) -> None:
    engine = DetectionEngine(baseline)
    inv = Investigator(baseline, online=online, use_llm=True)
    buf: "deque[Frame]" = deque()
    reported = set()

    if learn_seconds > 0 and not baseline.trusted_aps():
        print(f"[learn] listening {learn_seconds}s to build baseline "
              f"(ensure only your own network is active)...")
        frames = _sweep(iface, learn_seconds, channels)
        n = baseline.learn_from(frames)
        for ap in baseline.trusted_aps():
            print(f"   trusted: {ap['bssid']}  {ap['ssid']} ch{ap['channel']} {ap['security']}")
        print(f"[learn] baseline has {n} APs\n")

    print(f"[monitor] passive detection on {iface}"
          + (f", hopping {channels}" if channels else "")
          + " — Ctrl-C to stop\n")
    try:
        while True:
            batch = _sweep(iface, interval, channels)
            now = time.time()
            for fr in batch:
                baseline.record(fr)
                buf.append(fr)
            baseline.conn.commit()
            while buf and now - buf[0].ts > window:
                buf.popleft()
            events = engine.run(list(buf))
            new = [e for e in events if (e.attack.value, e.bssid) not in reported]
            for e in new:
                reported.add((e.attack.value, e.bssid))
            for v in inv.investigate_all(new):
                m = _MARK.get(v.label.value, "")
                e = v.event
                print(f"{m} {v.label.value.upper():<13} {v.confidence:>4.0%}  "
                      f"{e.attack.value:<12} {e.bssid}"
                      + (f"  '{e.ssid}'" if e.ssid else ""))
                print(f"      {v.reasoning}")
                if v.fix:
                    print(f"      FIX: {v.fix.description}")
                if telegram.send_verdict(v):
                    print("      (alert sent to Telegram)")
                print()
    except KeyboardInterrupt:
        print(f"\n[monitor] stopped. {len(reported)} distinct findings; "
              f"{len(baseline.trusted_aps())} APs trusted.")
