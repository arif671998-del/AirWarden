"""Shared data types for AirWarden.

Every layer (capture, detection, agent, response, alerting) speaks in terms of
these types so components stay decoupled. Nothing here depends on third-party
packages, so it runs on a bare Python install.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, List, Dict, Any


# ---------------------------------------------------------------------------
# 802.11 frame observation (normalised, source-agnostic)
# ---------------------------------------------------------------------------

class FrameType(str, Enum):
    BEACON = "beacon"
    PROBE_REQ = "probe_req"
    PROBE_RESP = "probe_resp"
    DEAUTH = "deauth"
    DISASSOC = "disassoc"
    AUTH = "auth"
    ASSOC_REQ = "assoc_req"
    ASSOC_RESP = "assoc_resp"
    DATA = "data"
    OTHER = "other"


class Security(str, Enum):
    OPEN = "open"
    WEP = "wep"
    WPA = "wpa"
    WPA2 = "wpa2"
    WPA3 = "wpa3"
    UNKNOWN = "unknown"


@dataclass
class Frame:
    """One normalised 802.11 management/data frame.

    Whether it came from a live monitor-mode adapter or a recorded pcap, the
    detectors only ever see this shape.
    """
    ts: float
    ftype: FrameType
    addr1: str = ""              # destination / receiver
    addr2: str = ""              # source / transmitter
    addr3: str = ""              # BSSID for most mgmt frames
    ssid: Optional[str] = None
    channel: Optional[int] = None
    security: Security = Security.UNKNOWN
    pmf: Optional[bool] = None   # 802.11w Protected Management Frames
    reason: Optional[int] = None # deauth/disassoc reason code
    rssi: Optional[int] = None   # dBm, from radiotap

    @property
    def bssid(self) -> str:
        return self.addr3

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["ftype"] = self.ftype.value
        d["security"] = self.security.value
        return d


# ---------------------------------------------------------------------------
# Detection events (what a rule detector emits)
# ---------------------------------------------------------------------------

class AttackType(str, Enum):
    DEAUTH_FLOOD = "deauth_flood"
    EVIL_TWIN = "evil_twin"
    ROGUE_AP = "rogue_ap"
    KARMA_PROBE = "karma_probe"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Evidence:
    """A single piece of supporting evidence, always traceable to frames."""
    kind: str                       # e.g. "frame_count", "bssid_mismatch"
    detail: str                     # human-readable
    frame_refs: List[int] = field(default_factory=list)  # indices into capture
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DetectionEvent:
    """Raised by a rule detector. Pre-verdict: the agent investigates these."""
    attack: AttackType
    severity: Severity
    ts: float
    bssid: str = ""
    ssid: Optional[str] = None
    channel: Optional[int] = None
    summary: str = ""
    evidence: List[Evidence] = field(default_factory=list)
    detector: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["attack"] = self.attack.value
        d["severity"] = self.severity.value
        d["evidence"] = [e.to_dict() for e in self.evidence]
        return d


# ---------------------------------------------------------------------------
# Verdicts (what the agent produces after investigating an event)
# ---------------------------------------------------------------------------

class VerdictLabel(str, Enum):
    CONFIRMED = "confirmed"       # strong evidence of attack
    SUSPECTED = "suspected"       # plausible, needs attention
    NEEDS_REVIEW = "needs_review" # weak evidence, do not auto-report
    BENIGN = "benign"             # investigated, no attack


@dataclass
class RecommendedFix:
    action: str                   # e.g. "enable_pmf", "block_bssid"
    description: str              # plain language
    target: str = ""              # router / interface
    reversible: bool = True
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ResponseState(str, Enum):
    NONE = "none"
    PROPOSED = "proposed"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    APPLIED = "applied"
    VERIFIED = "verified"
    REJECTED = "rejected"
    FAILED = "failed"


@dataclass
class Verdict:
    event: DetectionEvent
    label: VerdictLabel
    confidence: float             # 0.0 - 1.0
    reasoning: str = ""
    investigation_steps: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    fix: Optional[RecommendedFix] = None
    response_state: ResponseState = ResponseState.NONE
    created_ts: float = field(default_factory=time.time)
    id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "id": self.id,
            "event": self.event.to_dict(),
            "label": self.label.value,
            "confidence": round(self.confidence, 3),
            "reasoning": self.reasoning,
            "investigation_steps": self.investigation_steps,
            "evidence": [e.to_dict() for e in self.evidence],
            "fix": self.fix.to_dict() if self.fix else None,
            "response_state": self.response_state.value,
            "created_ts": self.created_ts,
        }
        return d
