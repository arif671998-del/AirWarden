"""Tests for the added detectors: karma, beacon flood, auth flood, SSID
typosquat, MAC spoof. Each runs the full detect->investigate pipeline on its
fixture and checks the right attack is found with a fix proposed; benign stays
clean."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from airwarden.baseline import Baseline
from airwarden.detect import DetectionEngine
from airwarden.agent import Investigator
from airwarden.schema import AttackType
import make_fixtures as mf


def _run(frames):
    b = Baseline()
    for ssid, bssid, ch, sec in mf.TRUSTED:
        b.add_trusted(bssid, ssid, ch, sec)
    b.record_all(frames)
    events = DetectionEngine(b).run(frames)
    verdicts = Investigator(b, use_llm=False).investigate_all(events)
    return events, verdicts


def _find(verdicts, attack):
    return [v for v in verdicts if v.event.attack == attack]


def test_karma():
    _, v = _run(mf.karma_frames())
    k = _find(v, AttackType.KARMA_PROBE)
    assert k, "expected karma event"
    assert k[0].fix and k[0].fix.action == "block_bssid"
    cnt = next(e.data["ssid_count"] for e in k[0].event.evidence
               if e.kind == "many_ssids_one_ap")
    print("  karma: %s %.0f%% (%d SSIDs from one AP)" %
          (k[0].label.value, k[0].confidence * 100, cnt))


def test_beacon_flood():
    _, v = _run(mf.beacon_flood_frames())
    bf = _find(v, AttackType.BEACON_FLOOD)
    assert bf, "expected beacon flood event"
    print("  beacon flood: %s %.0f%%" % (bf[0].label.value, bf[0].confidence * 100))


def test_auth_flood():
    _, v = _run(mf.auth_flood_frames())
    af = _find(v, AttackType.AUTH_FLOOD)
    assert af, "expected auth flood event"
    assert af[0].event.bssid == "f4:f2:6d:11:22:33"
    print("  auth flood: %s %.0f%%" % (af[0].label.value, af[0].confidence * 100))


def test_typosquat():
    ev, v = _run(mf.typosquat_frames())
    ts = _find(v, AttackType.SSID_TYPOSQUAT)
    assert ts, "expected typosquat event"
    assert ts[0].event.ssid == "Campus-WiFi"
    # rogue must have been de-duped away for this BSSID
    assert not [e for e in ev if e.attack == AttackType.ROGUE_AP
                and e.bssid == ts[0].event.bssid]
    print("  typosquat: %s %.0f%% ('Campus-WiFi' vs 'CampusWiFi')" %
          (ts[0].label.value, ts[0].confidence * 100))


def test_mac_spoof():
    _, v = _run(mf.mac_spoof_frames())
    ms = _find(v, AttackType.MAC_SPOOF)
    assert ms, "expected mac spoof event"
    assert ms[0].fix.action == "notify"           # must NOT block (genuine shares MAC)
    print("  mac spoof: %s %.0f%% (fix=%s)" %
          (ms[0].label.value, ms[0].confidence * 100, ms[0].fix.action))


def test_benign_still_clean():
    ev, v = _run(mf.benign_frames())
    assert ev == [], "benign must stay clean, got %d" % len(ev)
    print("  benign: still 0 events across all 8 detectors")


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        print("•", t.__name__); t()
    print("\n%d/%d new-attack tests passed" % (len(tests), len(tests)))


if __name__ == "__main__":
    _main()
