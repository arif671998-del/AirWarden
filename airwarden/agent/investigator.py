"""The investigation agent.

Structured as discrete nodes — plan -> investigate -> assess -> recommend ->
explain — so the same logic runs standalone (here) or as a LangGraph StateGraph
(graph.py). The agent decides which checks to run for each attack type, gathers
evidence, scores confidence, and only proposes a fix (always approval-gated)
when the evidence is strong enough. Weak evidence is labelled NEEDS_REVIEW and
never auto-reported as an attack.
"""
from __future__ import annotations

import uuid
from typing import List, Dict, Any, Optional

from ..schema import (DetectionEvent, Verdict, VerdictLabel, AttackType,
                      Severity, Evidence, RecommendedFix, ResponseState)
from . import tools
from .llm import explain as llm_explain

# which tools to run for each attack type ("the agent plans its own checks")
PLAN: Dict[AttackType, List[str]] = {
    AttackType.EVIL_TWIN: ["check_baseline", "beacon_comparison",
                            "vendor_lookup", "signal_history", "portal_probe"],
    AttackType.DEAUTH_FLOOD: ["check_baseline", "deauth_profile", "pmf_support"],
    AttackType.ROGUE_AP: ["check_baseline", "vendor_lookup", "signal_history"],
    AttackType.KARMA_PROBE: ["check_baseline", "vendor_lookup", "signal_history"],
    AttackType.SSID_TYPOSQUAT: ["check_baseline", "vendor_lookup", "signal_history"],
    AttackType.BEACON_FLOOD: ["check_baseline"],
    AttackType.AUTH_FLOOD: ["check_baseline"],
    AttackType.MAC_SPOOF: ["check_baseline", "signal_history"],
}

_BASE_CONF = {Severity.HIGH: 0.55, Severity.MEDIUM: 0.40,
              Severity.LOW: 0.25, Severity.INFO: 0.10}


class Investigator:
    def __init__(self, baseline, online: bool = False, use_llm: bool = True):
        self.baseline = baseline
        self.online = online
        self.use_llm = use_llm

    # -- node 1: plan ------------------------------------------------------
    def _plan(self, event: DetectionEvent) -> List[str]:
        return PLAN.get(event.attack, ["check_baseline"])

    # -- node 2: investigate ----------------------------------------------
    def _investigate(self, event: DetectionEvent, plan: List[str]):
        gathered: List[Evidence] = []
        steps: List[str] = []
        for name in plan:
            fn = getattr(tools, name)
            if name == "portal_probe":
                res = fn(event, self.baseline, online=self.online)
            else:
                res = fn(event, self.baseline)
            if res:
                gathered.append(res)
                steps.append(f"{name}: {res.detail}")
            else:
                steps.append(f"{name}: no data")
        return gathered, steps

    # -- node 3: assess ----------------------------------------------------
    def _assess(self, event: DetectionEvent, gathered: List[Evidence]):
        conf = _BASE_CONF.get(event.severity, 0.3)
        kinds = {e.kind: e for e in gathered}
        detector_kinds = {e.kind for e in event.evidence}

        if event.attack == AttackType.EVIL_TWIN:
            if "security_downgrade" in detector_kinds:
                conf += 0.25
            if "pmwani_branding" in detector_kinds:
                conf += 0.20
            if "vendor_mismatch" in detector_kinds:
                conf += 0.10
            bc = kinds.get("beacon_comparison")
            if bc and bc.data.get("diffs"):
                conf += 0.10
            pp = kinds.get("portal_probe")
            if pp and pp.data.get("portal"):
                conf += 0.20
            sh = kinds.get("signal_history")
            if sh and sh.data.get("mean_rssi", -100) > -45:
                conf += 0.05
        elif event.attack == AttackType.DEAUTH_FLOOD:
            if kinds.get("deauth_profile"):
                conf += 0.20
            pmf = kinds.get("pmf_support")
            if pmf and pmf.data.get("pmf") is False:
                conf += 0.15
            bc = kinds.get("baseline_check")
            if bc and bc.data.get("trusted"):
                conf += 0.10
        elif event.attack == AttackType.ROGUE_AP:
            if "pmwani_branding" in detector_kinds:
                conf += 0.25
            if "open_network" in detector_kinds:
                conf += 0.10
        elif event.attack == AttackType.KARMA_PROBE:
            d = next((e for e in event.evidence
                      if e.kind == "many_ssids_one_ap"), None)
            if d and d.data.get("ssid_count", 0) >= 6:
                conf += 0.20
            else:
                conf += 0.10
        elif event.attack == AttackType.SSID_TYPOSQUAT:
            d = next((e for e in event.evidence
                      if e.kind == "lookalike_ssid"), None)
            if d and d.data.get("match", "").startswith("homoglyph"):
                conf += 0.25            # identical-looking name is a strong tell
            else:
                conf += 0.20
        elif event.attack == AttackType.BEACON_FLOOD:
            if "ap_surge" in detector_kinds:
                conf += 0.25
        elif event.attack == AttackType.AUTH_FLOOD:
            if "request_burst" in detector_kinds:
                conf += 0.20
            if "targets_trusted_ap" in detector_kinds:
                conf += 0.10
        elif event.attack == AttackType.MAC_SPOOF:
            if "seqnum_regression" in detector_kinds:
                conf += 0.25

        conf = max(0.0, min(0.98, conf))
        if conf >= 0.80:
            label = VerdictLabel.CONFIRMED
        elif conf >= 0.55:
            label = VerdictLabel.SUSPECTED
        elif conf >= 0.35:
            label = VerdictLabel.NEEDS_REVIEW
        else:
            label = VerdictLabel.BENIGN
        return conf, label

    # -- node 4: recommend -------------------------------------------------
    def _recommend(self, event: DetectionEvent, label: VerdictLabel,
                   gathered: List[Evidence]) -> Optional[RecommendedFix]:
        if label not in (VerdictLabel.CONFIRMED, VerdictLabel.SUSPECTED):
            return None  # weak evidence -> no action proposed
        if event.attack == AttackType.DEAUTH_FLOOD:
            return RecommendedFix(
                action="enable_pmf",
                description=f"Enable 802.11w (Protected Management Frames) on "
                            f"'{self._ssid_of(event)}' so spoofed deauth frames "
                            f"are rejected.",
                target=event.bssid, reversible=True,
                params={"bssid": event.bssid, "ieee80211w": 1})
        if event.attack == AttackType.EVIL_TWIN:
            return RecommendedFix(
                action="block_bssid",
                description=f"Add impostor {event.bssid} to the deny list and "
                            f"warn users that '{event.ssid}' has a fake twin. "
                            f"Confirm 802.11w is on for the genuine AP.",
                target=event.bssid, reversible=True,
                params={"bssid": event.bssid, "ssid": event.ssid})
        if event.attack == AttackType.ROGUE_AP:
            return RecommendedFix(
                action="notify_and_blocklist",
                description=f"Flag unauthorised AP {event.bssid} ('{event.ssid}') "
                            f"to the operator; blocklist if it persists.",
                target=event.bssid, reversible=True,
                params={"bssid": event.bssid, "ssid": event.ssid})
        if event.attack in (AttackType.KARMA_PROBE, AttackType.SSID_TYPOSQUAT):
            return RecommendedFix(
                action="block_bssid",
                description=(f"Block impostor {event.bssid} and warn users"
                             + (f" that '{event.ssid}' mimics a trusted network."
                                if event.attack == AttackType.SSID_TYPOSQUAT
                                else " — it impersonates many saved networks.")),
                target=event.bssid, reversible=True,
                params={"bssid": event.bssid, "ssid": event.ssid})
        if event.attack == AttackType.AUTH_FLOOD:
            return RecommendedFix(
                action="notify",
                description=f"Auth/assoc flood on {event.bssid}: enable AP-side "
                            f"association rate-limiting / client isolation and "
                            f"alert the operator (sources are likely spoofed).",
                target=event.bssid, reversible=True, params={"bssid": event.bssid})
        if event.attack == AttackType.BEACON_FLOOD:
            return RecommendedFix(
                action="notify",
                description="Beacon flood in progress: hundreds of fake APs can't "
                            "be blocked individually — move clients to a known "
                            "5 GHz channel, keep PMF on, and locate the source.",
                target="(area)", reversible=True, params={})
        if event.attack == AttackType.MAC_SPOOF:
            return RecommendedFix(
                action="notify",
                description=f"Two radios share BSSID {event.bssid}. Don't block it "
                            f"(that also blocks the genuine AP) — verify 802.11w is "
                            f"on, consider 802.1X, and physically locate the spoofer.",
                target=event.bssid, reversible=True, params={"bssid": event.bssid})
        return None

    def _ssid_of(self, event: DetectionEvent) -> str:
        if event.ssid:
            return event.ssid
        rec = self.baseline.get(event.bssid)
        return rec["ssid"] if rec else event.bssid

    # -- node 5: explain ---------------------------------------------------
    def _explain(self, event, label, conf, gathered) -> str:
        facts = [e.detail for e in gathered]
        base = (f"{event.attack.value.replace('_',' ').title()} on "
                f"{event.bssid}: classified {label.value} "
                f"(confidence {conf:.0%}). Based on: " + "; ".join(facts) + ".")
        if self.use_llm:
            narrated = llm_explain(event.to_dict(), label.value, conf, facts)
            if narrated:
                return narrated
        return base

    # -- orchestrate -------------------------------------------------------
    def investigate(self, event: DetectionEvent) -> Verdict:
        plan = self._plan(event)
        gathered, steps = self._investigate(event, plan)
        conf, label = self._assess(event, gathered)
        fix = self._recommend(event, label, gathered)
        reasoning = self._explain(event, label, conf, gathered)
        state = ResponseState.PROPOSED if fix else ResponseState.NONE
        return Verdict(
            event=event, label=label, confidence=conf, reasoning=reasoning,
            investigation_steps=steps,
            evidence=list(event.evidence) + gathered,
            fix=fix, response_state=state, id=uuid.uuid4().hex[:8])

    def investigate_all(self, events: List[DetectionEvent]) -> List[Verdict]:
        return [self.investigate(e) for e in events]
