"""Optional LangGraph wrapper.

The Investigator's nodes (plan -> investigate -> assess -> recommend ->
explain) map directly onto a LangGraph StateGraph. This module builds that
graph when `langgraph` is installed; otherwise importing it raises a clear
error and callers fall back to Investigator.investigate() directly, which runs
the identical logic. This keeps the proposal's LangGraph architecture real
while letting the system run with zero extra dependencies.
"""
from __future__ import annotations

from typing import TypedDict, List, Optional, Any

from ..schema import DetectionEvent, Verdict
from .investigator import Investigator


class InvState(TypedDict, total=False):
    event: DetectionEvent
    plan: List[str]
    gathered: List[Any]
    steps: List[str]
    confidence: float
    label: Any
    fix: Optional[Any]
    reasoning: str
    verdict: Verdict


def build_graph(investigator: Investigator):
    """Return a compiled LangGraph app, or raise ImportError if unavailable."""
    from langgraph.graph import StateGraph, START, END  # noqa: F401

    g = StateGraph(InvState)

    def plan(s): s["plan"] = investigator._plan(s["event"]); return s
    def investigate(s):
        s["gathered"], s["steps"] = investigator._investigate(s["event"], s["plan"]); return s
    def assess(s):
        s["confidence"], s["label"] = investigator._assess(s["event"], s["gathered"]); return s
    def recommend(s):
        s["fix"] = investigator._recommend(s["event"], s["label"], s["gathered"]); return s
    def explain(s):
        s["reasoning"] = investigator._explain(
            s["event"], s["label"], s["confidence"], s["gathered"]); return s

    for name, fn in [("plan", plan), ("investigate", investigate),
                     ("assess", assess), ("recommend", recommend),
                     ("explain", explain)]:
        g.add_node(name, fn)
    g.add_edge(START, "plan")
    g.add_edge("plan", "investigate")
    g.add_edge("investigate", "assess")
    g.add_edge("assess", "recommend")
    g.add_edge("recommend", "explain")
    g.add_edge("explain", END)
    return g.compile()


def available() -> bool:
    try:
        import langgraph  # noqa: F401
        return True
    except Exception:
        return False
