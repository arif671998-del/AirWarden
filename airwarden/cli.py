"""AirWarden command-line runner.

Usage:
  python3 -m airwarden analyze <capture.pcap> [--learn <clean.pcap>]
                                              [--baseline <db>] [--json out.json]
  python3 -m airwarden learn <clean.pcap> --baseline <db>

`analyze` runs the full pipeline (detect -> investigate) and prints a verdict
report. With --learn it first builds the trusted baseline from a clean capture;
otherwise it loads/initialises the given baseline DB.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import pcap
from .baseline import Baseline
from .detect import DetectionEngine
from .agent import Investigator

_LABEL_MARK = {"confirmed": "[!]", "suspected": "[?]",
               "needs_review": "[.]", "benign": "[ ]"}


def _load_baseline(args) -> Baseline:
    b = Baseline(args.baseline or ":memory:")
    if getattr(args, "learn", None):
        frames = pcap.read_pcap(args.learn)
        n = b.learn_from(frames)
        print(f"baseline: learned {n} authorised APs from {args.learn}", file=sys.stderr)
    return b


def cmd_learn(args):
    b = Baseline(args.baseline)
    frames = pcap.read_pcap(args.capture)
    n = b.learn_from(frames)
    print(f"learned {n} APs into {args.baseline}")
    for ap in b.trusted_aps():
        print(f"  {ap['bssid']}  {ap['ssid']:<16} ch{ap['channel']} "
              f"{ap['security']} ({ap['vendor']})")


def cmd_analyze(args):
    b = _load_baseline(args)
    frames = pcap.read_pcap(args.capture)
    b.record_all(frames)
    events = DetectionEngine(b).run(frames)
    verdicts = Investigator(b, online=args.online,
                            use_llm=not args.no_llm).investigate_all(events)

    print(f"\nAirWarden — analysed {len(frames)} frames from {args.capture}")
    print(f"{len(b.trusted_aps())} authorised APs; {len(verdicts)} events\n")
    for v in verdicts:
        mark = _LABEL_MARK.get(v.label.value, "")
        e = v.event
        print(f"{mark} {v.label.value.upper():<13} {v.confidence:>4.0%}  "
              f"{e.attack.value:<12} {e.bssid}"
              + (f"  '{e.ssid}'" if e.ssid else ""))
        print(f"      {v.reasoning}")
        if v.fix:
            print(f"      FIX ({v.response_state.value}): {v.fix.description}")
        print()

    if args.json:
        with open(args.json, "w") as fh:
            json.dump([v.to_dict() for v in verdicts], fh, indent=2)
        print(f"wrote {args.json}", file=sys.stderr)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="airwarden")
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("analyze", help="detect + investigate a capture")
    pa.add_argument("capture")
    pa.add_argument("--learn", help="clean pcap to learn the baseline from")
    pa.add_argument("--baseline", help="sqlite baseline db (default in-memory)")
    pa.add_argument("--json", help="write full verdicts as JSON")
    pa.add_argument("--online", action="store_true",
                    help="allow passive portal probe (real hardware only)")
    pa.add_argument("--no-llm", action="store_true", help="skip LLM narration")
    pa.set_defaults(func=cmd_analyze)

    pl = sub.add_parser("learn", help="build a baseline from a clean capture")
    pl.add_argument("capture")
    pl.add_argument("--baseline", required=True)
    pl.set_defaults(func=cmd_learn)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
