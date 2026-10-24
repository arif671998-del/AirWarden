"""Response-layer tests: dry-run command generation, approval lifecycle, and
re-scan verification (approve a fix, then re-scan a clean capture and confirm
the attack indicator is gone)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from airwarden.baseline import Baseline
from airwarden.detect import DetectionEngine
from airwarden.agent import Investigator
from airwarden.respond import ApprovalManager, OpenWrtRouter
from airwarden.schema import ResponseState, AttackType
import make_fixtures as mf


def _setup(frames):
    b = Baseline()
    for ssid, bssid, ch, sec in mf.TRUSTED:
        b.add_trusted(bssid, ssid, ch, sec)
    b.record_all(frames)
    events = DetectionEngine(b).run(frames)
    verdicts = Investigator(b, use_llm=False).investigate_all(events)
    mgr = ApprovalManager(OpenWrtRouter(dry_run=True), baseline=b)
    mgr.load(verdicts)
    return b, mgr


def test_deauth_fix_commands_and_verify():
    b, mgr = _setup(mf.deauth_flood_frames())
    v = [x for x in mgr.list() if x.event.attack == AttackType.DEAUTH_FLOOD][0]
    assert v.response_state == ResponseState.AWAITING_APPROVAL
    # approve, verifying against a clean post-fix capture (no flood)
    res = mgr.approve(v.id, rescan_frames=mf.benign_frames())
    assert res["ok"] is True
    assert any("ieee80211w='2'" in c for c in res["apply"]["commands"])
    assert res["apply"]["dry_run"] is True
    assert v.response_state == ResponseState.VERIFIED
    assert "clean" in res["verification"]["note"]
    print("  deauth: applied %s cmds (dry-run), verified clean"
          % len(res["apply"]["commands"]))


def test_evil_twin_block_and_verify():
    b, mgr = _setup(mf.evil_twin_frames())
    v = [x for x in mgr.list() if x.event.attack == AttackType.EVIL_TWIN][0]
    res = mgr.approve(v.id, rescan_frames=mf.benign_frames())
    assert res["ok"] is True
    assert any("macfilter='deny'" in c for c in res["apply"]["commands"])
    assert any("de:ad:be:ef:00:01" in c for c in res["apply"]["commands"])
    assert v.response_state == ResponseState.VERIFIED
    print("  evil twin: impostor blocked (dry-run), verified clean")


def test_verify_fails_if_attack_persists():
    b, mgr = _setup(mf.deauth_flood_frames())
    v = [x for x in mgr.list() if x.event.attack == AttackType.DEAUTH_FLOOD][0]
    # re-scan with the flood STILL present -> verification must fail
    res = mgr.approve(v.id, rescan_frames=mf.deauth_flood_frames())
    assert res["ok"] is False
    assert v.response_state == ResponseState.FAILED
    print("  verification correctly FAILS when attack persists")


def test_reject():
    b, mgr = _setup(mf.evil_twin_frames())
    v = [x for x in mgr.list() if x.event.attack == AttackType.EVIL_TWIN][0]
    mgr.reject(v.id)
    assert v.response_state == ResponseState.REJECTED
    print("  reject -> REJECTED, no commands run")


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        print("•", t.__name__); t()
    print("\n%d/%d response tests passed" % (len(tests), len(tests)))


if __name__ == "__main__":
    _main()
