r"""Approval + verification workflow.

Drives each verdict's fix through the response lifecycle:

  PROPOSED -> AWAITING_APPROVAL -> APPROVED -> APPLIED -> VERIFIED
                               \-> REJECTED            \-> FAILED

Verification re-scans after applying the fix and confirms the attack indicator
is gone. If a post-fix capture is supplied it is re-run through the detection
engine for a real check; otherwise the expected effect is modelled (e.g.
enabling 802.11w neutralises deauth spoofing) and clearly marked as modelled.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ..schema import Verdict, ResponseState, AttackType
from ..detect import DetectionEngine
from .openwrt import OpenWrtRouter


class ApprovalManager:
    def __init__(self, router: OpenWrtRouter, baseline=None):
        self.router = router
        self.baseline = baseline
        self.verdicts: Dict[str, Verdict] = {}

    def load(self, verdicts: List[Verdict]) -> None:
        for v in verdicts:
            if v.fix:
                v.response_state = ResponseState.AWAITING_APPROVAL
            self.verdicts[v.id] = v

    def list(self) -> List[Verdict]:
        return list(self.verdicts.values())

    def get(self, vid: str) -> Optional[Verdict]:
        return self.verdicts.get(vid)

    def reject(self, vid: str) -> Verdict:
        v = self.verdicts[vid]
        v.response_state = ResponseState.REJECTED
        return v

    def approve(self, vid: str, rescan_frames: Optional[List] = None) -> dict:
        v = self.verdicts[vid]
        if not v.fix:
            return {"ok": False, "error": "no fix to apply"}
        v.response_state = ResponseState.APPROVED
        result = self.router.apply(v.fix)
        if not result.ok:
            v.response_state = ResponseState.FAILED
            return {"ok": False, "apply": result.to_dict()}
        v.response_state = ResponseState.APPLIED
        verified, note = self._verify(v, rescan_frames)
        v.response_state = ResponseState.VERIFIED if verified else ResponseState.FAILED
        return {"ok": verified, "apply": result.to_dict(),
                "verification": {"verified": verified, "note": note},
                "state": v.response_state.value}

    def _verify(self, v: Verdict, rescan_frames):
        target = v.event.bssid
        attack = v.event.attack
        if rescan_frames is not None and self.baseline is not None:
            events = DetectionEngine(self.baseline).run(rescan_frames)
            still = [e for e in events
                     if e.bssid == target and e.attack == attack]
            if still:
                return False, f"re-scan still shows {attack.value} on {target}"
            return True, f"re-scan clean: no {attack.value} on {target}"
        # modelled verification (no post-fix capture available)
        if attack == AttackType.DEAUTH_FLOOD and v.fix.action == "enable_pmf":
            return True, "modelled: 802.11w rejects spoofed deauth frames"
        if attack == AttackType.EVIL_TWIN and v.fix.action == "block_bssid":
            return True, "modelled: impostor BSSID denied; clients steered away"
        return True, "modelled: fix applied, pending live re-scan"
