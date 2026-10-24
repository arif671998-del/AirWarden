"""LangGraph path test (OPTIONAL extra).

Skips cleanly if `langgraph` isn't installed. When it is, this runs a real
DetectionEvent through the compiled StateGraph and checks it produces the same
kind of verdict the deterministic engine does.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from airwarden.agent.graph import available, build_graph
from airwarden.agent import Investigator
from airwarden.baseline import Baseline
from airwarden.detect import DetectionEngine
import make_fixtures as mf


def main():
    if not available():
        print("langgraph not installed — SKIPPED "
              "(run `pip install langgraph` to enable this path)")
        return
    b = Baseline()
    for ssid, bssid, ch, sec in mf.TRUSTED:
        b.add_trusted(bssid, ssid, ch, sec)
    frames = mf.evil_twin_frames()
    b.record_all(frames)
    event = DetectionEngine(b).run(frames)[0]
    app = build_graph(Investigator(b, use_llm=False))
    out = app.invoke({"event": event})
    assert out["label"].value in ("confirmed", "suspected"), out["label"]
    assert out["fix"] is not None
    print("• LangGraph StateGraph ran end-to-end: %s %d%%, fix=%s"
          % (out["label"].value, round(out["confidence"] * 100),
             out["fix"].action))
    print("\nlanggraph path OK")


if __name__ == "__main__":
    main()
