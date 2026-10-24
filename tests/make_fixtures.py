"""Generate synthetic .pcap fixtures for the detectors and the demo.

These are OFFLINE TEST DATA. The frames are written to files and never
transmitted; no radio is ever touched. They model a small network plus three
attacks so the detectors can be exercised deterministically and so judges can
open the captures in Wireshark.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from airwarden.schema import Frame, FrameType, Security
from airwarden import pcap

FIX_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

# --- the authorised environment -------------------------------------------
TRUSTED = [
    # ssid, bssid, channel, security
    ("CampusWiFi",     "f4:f2:6d:11:22:33", 6,  Security.WPA2),
    ("HostelNet",      "ac:22:0b:aa:bb:cc", 1,  Security.WPA2),
    ("PMWANI_Cafe01",  "74:da:88:00:11:22", 11, Security.WPA2),
]


def beacon(ssid, bssid, ch, sec, ts, rssi=-45, pmf=False):
    return Frame(ts=ts, ftype=FrameType.BEACON, addr1="ff:ff:ff:ff:ff:ff",
                 addr2=bssid, addr3=bssid, ssid=ssid, channel=ch,
                 security=sec, pmf=pmf, rssi=rssi)


def deauth(bssid, client, ts, reason=7, rssi=-60):
    return Frame(ts=ts, ftype=FrameType.DEAUTH, addr1=client, addr2=bssid,
                 addr3=bssid, reason=reason, rssi=rssi)


def benign_frames():
    """Clean capture: trusted APs beaconing, a little data, a couple of
    ordinary deauths (well below the flood threshold)."""
    frames = []
    t = 0.0
    for cycle in range(12):
        for ssid, bssid, ch, sec in TRUSTED:
            frames.append(beacon(ssid, bssid, ch, sec, t, rssi=-40 - cycle % 5))
            t += 0.1
    # a few legitimate deauths spread out over time (roaming clients)
    for k in range(3):
        frames.append(deauth("f4:f2:6d:11:22:33", "aa:bb:cc:dd:ee:0%d" % k,
                             5.0 + k * 3.0))
    return frames


def deauth_flood_frames():
    frames = benign_frames()
    t = 20.0
    for k in range(60):                       # 60 deauths in ~6s -> flood
        frames.append(deauth("f4:f2:6d:11:22:33",
                             "aa:bb:cc:dd:ee:%02d" % (k % 8), t))
        t += 0.1
    return frames


def evil_twin_frames():
    frames = benign_frames()
    t = 25.0
    for k in range(10):                       # impostor cloning CampusWiFi, OPEN
        frames.append(beacon("CampusWiFi", "de:ad:be:ef:00:01", 6,
                             Security.OPEN, t, rssi=-55))
        t += 0.5
    return frames


def rogue_ap_frames():
    frames = benign_frames()
    t = 25.0
    for k in range(8):                        # brand-new open network
        frames.append(beacon("FreeAirport_WiFi", "00:11:22:33:44:55", 3,
                             Security.OPEN, t, rssi=-65))
        t += 0.5
    for k in range(8):                        # PMWANI-branded rogue
        frames.append(beacon("PMWANI_FreeFast", "12:34:56:78:9a:bc", 9,
                             Security.OPEN, t, rssi=-58))
        t += 0.5
    return frames


FIXTURES = {
    "benign.pcap": benign_frames,
    "deauth_flood.pcap": deauth_flood_frames,
    "evil_twin.pcap": evil_twin_frames,
    "rogue_ap.pcap": rogue_ap_frames,
}


def build_all():
    os.makedirs(FIX_DIR, exist_ok=True)
    for name, fn in FIXTURES.items():
        path = os.path.join(FIX_DIR, name)
        pcap.write_pcap(path, fn())
        print("wrote", path, "(%d frames)" % len(fn()))


if __name__ == "__main__":
    build_all()
