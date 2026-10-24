"""Detector tests. Run with:  python3 -m pytest tests/  (or python3 tests/test_detect.py)

Proves each detector fires on its attack fixture, that the benign capture is
clean (no false alarms), and that the pcap codec round-trips.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from airwarden import pcap
from airwarden.baseline import Baseline
from airwarden.detect import DetectionEngine
from airwarden.schema import AttackType, Severity
import make_fixtures as mf


def _baseline():
    b = Baseline()
    for ssid, bssid, ch, sec in mf.TRUSTED:
        b.add_trusted(bssid, ssid, ch, sec)
    return b


def _run(frames):
    b = _baseline()
    b.record_all(frames)
    return DetectionEngine(b).run(frames)


def test_pcap_roundtrip(tmp_path=None):
    frames = mf.benign_frames()
    path = os.path.join(mf.FIX_DIR, "_roundtrip.pcap")
    os.makedirs(mf.FIX_DIR, exist_ok=True)
    pcap.write_pcap(path, frames)
    back = pcap.read_pcap(path)
    beacons_in = [f for f in frames if f.ftype.value == "beacon"]
    beacons_out = [f for f in back if f.ftype.value == "beacon"]
    assert len(beacons_out) == len(beacons_in)
    b0 = beacons_out[0]
    assert b0.ssid in [t[0] for t in mf.TRUSTED]
    assert b0.security.value == "wpa2"
    assert b0.channel in (1, 6, 11)
    os.remove(path)
    print("  pcap round-trip: %d frames, ssid/security/channel preserved" % len(back))


def test_benign_clean():
    events = _run(mf.benign_frames())
    assert events == [], "benign capture should raise no events, got %d" % len(events)
    print("  benign: 0 events (no false alarms)")


def test_deauth_flood():
    events = _run(mf.deauth_flood_frames())
    floods = [e for e in events if e.attack == AttackType.DEAUTH_FLOOD]
    assert floods, "expected a deauth flood event"
    e = floods[0]
    assert e.severity == Severity.HIGH          # targets a trusted AP
    assert e.bssid == "f4:f2:6d:11:22:33"
    counts = [ev.data.get("count", 0) for ev in e.evidence if ev.kind == "frame_count"]
    assert counts and counts[0] >= 20
    print("  deauth flood: %s (count=%d)" % (e.severity.value, counts[0]))


def test_evil_twin():
    events = _run(mf.evil_twin_frames())
    twins = [e for e in events if e.attack == AttackType.EVIL_TWIN]
    assert twins, "expected an evil twin event"
    e = twins[0]
    assert e.ssid == "CampusWiFi"
    assert e.bssid == "de:ad:be:ef:00:01"
    kinds = {ev.kind for ev in e.evidence}
    assert "ssid_clone" in kinds
    assert "security_downgrade" in kinds         # trusted WPA2 vs impostor OPEN
    assert e.severity == Severity.HIGH
    print("  evil twin: %s, evidence=%s" % (e.severity.value, sorted(kinds)))


def test_rogue_ap_and_pmwani():
    events = _run(mf.rogue_ap_frames())
    rogues = [e for e in events if e.attack == AttackType.ROGUE_AP]
    ssids = {e.ssid: e for e in rogues}
    assert "FreeAirport_WiFi" in ssids
    assert "PMWANI_FreeFast" in ssids
    assert ssids["PMWANI_FreeFast"].severity == Severity.HIGH   # branding abuse
    assert ssids["FreeAirport_WiFi"].severity == Severity.MEDIUM  # open network
    print("  rogue AP: %d unknown networks; PMWANI rogue = HIGH" % len(rogues))


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        print("•", t.__name__)
        t()
        passed += 1
    print("\n%d/%d tests passed" % (passed, len(tests)))


if __name__ == "__main__":
    _main()
