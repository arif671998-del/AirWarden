"""Agent investigation tests. Verifies the investigator turns detection events
into sensible verdicts with confidence, investigation steps, and approval-gated
fixes — all offline (no LLM)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from airwarden.baseline import Baseline
from airwarden.detect import DetectionEngine
from airwarden.agent import Investigator
from airwarden.schema import VerdictLabel, AttackType, ResponseState
import make_fixtures as mf


def _pipeline(frames):
    b = Baseline()
    for ssid, bssid, ch, sec in mf.TRUSTED:
        b.add_trusted(bssid, ssid, ch, sec)   # PMF not set -> pmf None/False
    b.record_all(frames)
    events = DetectionEngine(b).run(frames)
    verdicts = Investigator(b, online=False, use_llm=False).investigate_all(events)
    return verdicts


def test_evil_twin_verdict():
    v = [x for x in _pipeline(mf.evil_twin_frames())
         if x.event.attack == AttackType.EVIL_TWIN][0]
    assert v.label in (VerdictLabel.CONFIRMED, VerdictLabel.SUSPECTED)
    assert v.confidence >= 0.55
    assert v.fix is not None and v.fix.action == "block_bssid"
    assert v.response_state == ResponseState.PROPOSED
    assert any("beacon_comparison" in s for s in v.investigation_steps)
    print("  evil twin -> %s %.0f%%, fix=%s" %
          (v.label.value, v.confidence * 100, v.fix.action))


def test_deauth_verdict():
    v = [x for x in _pipeline(mf.deauth_flood_frames())
         if x.event.attack == AttackType.DEAUTH_FLOOD][0]
    assert v.label == VerdictLabel.CONFIRMED
    assert v.fix.action == "enable_pmf"           # PMF off on target -> correct fix
    assert v.response_state == ResponseState.PROPOSED
    print("  deauth flood -> %s %.0f%%, fix=%s" %
          (v.label.value, v.confidence * 100, v.fix.action))


def test_rogue_pmwani_verdict():
    vs = _pipeline(mf.rogue_ap_frames())
    pm = [x for x in vs if x.event.ssid == "PMWANI_FreeFast"][0]
    assert pm.confidence >= 0.55
    assert pm.fix is not None
    print("  PMWANI rogue -> %s %.0f%%" % (pm.label.value, pm.confidence * 100))


def test_benign_no_verdicts():
    assert _pipeline(mf.benign_frames()) == []
    print("  benign -> no events, no verdicts")


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        print("•", t.__name__); t()
    print("\n%d/%d agent tests passed" % (len(tests), len(tests)))


if __name__ == "__main__":
    _main()
