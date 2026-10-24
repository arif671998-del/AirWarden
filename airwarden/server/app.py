"""AirWarden operator console backend.

A dependency-free HTTP server exposing:
  GET  /                 -> dashboard (web/index.html)
  GET  /api/state        -> trusted APs, current verdicts, stats, scenarios
  POST /api/scan         -> {"scenario": name}  run pipeline on a capture
  POST /api/approve      -> {"id": vid}          approve + apply + verify
  POST /api/reject       -> {"id": vid}
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .. import pcap
from ..baseline import Baseline
from ..detect import DetectionEngine
from ..agent import Investigator
from ..respond import ApprovalManager, OpenWrtRouter
from .. import alert
from ..alert import telegram, email_alert
from ..alert.format import summarize

_HERE = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.normpath(os.path.join(_HERE, "..", "..", "web"))
FIX_DIR = os.path.normpath(os.path.join(_HERE, "..", "..", "tests", "fixtures"))

SCENARIOS = {
    "benign": ("Normal traffic", "benign.pcap"),
    "deauth_flood": ("Deauth flood", "deauth_flood.pcap"),
    "evil_twin": ("Evil twin", "evil_twin.pcap"),
    "rogue_ap": ("Rogue + PMWANI AP", "rogue_ap.pcap"),
    "karma": ("Karma / MANA", "karma.pcap"),
    "beacon_flood": ("Beacon flood", "beacon_flood.pcap"),
    "auth_flood": ("Auth / assoc flood", "auth_flood.pcap"),
    "typosquat": ("SSID typosquat", "typosquat.pcap"),
    "mac_spoof": ("MAC spoofing", "mac_spoof.pcap"),
}


class AppState:
    def __init__(self, baseline_pcap: str = None, online: bool = False):
        self.lock = threading.Lock()
        self.online = online
        self.baseline = Baseline()
        bp = baseline_pcap or os.path.join(FIX_DIR, "benign.pcap")
        if os.path.exists(bp):
            self.baseline.learn_from(pcap.read_pcap(bp))
        self.router = OpenWrtRouter(dry_run=not online)
        self.mgr = ApprovalManager(self.router, baseline=self.baseline)
        self.events_log = []

    def scan(self, scenario: str) -> dict:
        label, fname = SCENARIOS.get(scenario, SCENARIOS["benign"])
        path = os.path.join(FIX_DIR, fname)
        frames = pcap.read_pcap(path)
        with self.lock:
            self.baseline.record_all(frames)
            events = DetectionEngine(self.baseline).run(frames)
            verdicts = Investigator(self.baseline, online=self.online,
                                    use_llm=True).investigate_all(events)
            self.mgr.verdicts.clear()
            self.mgr.load(verdicts)
            self.events_log.append(f"scan '{label}': {len(frames)} frames, "
                                   f"{len(verdicts)} events")
        for v in verdicts:               # push alerts (no-op if unconfigured)
            if v.fix:
                alert.send_all(v)
        return {"scenario": scenario, "frames": len(frames),
                "verdicts": [v.to_dict() for v in verdicts]}

    def approve(self, vid: str) -> dict:
        with self.lock:
            # model the fix working by re-scanning clean traffic
            clean = pcap.read_pcap(os.path.join(FIX_DIR, "benign.pcap"))
            return self.mgr.approve(vid, rescan_frames=clean)

    def reject(self, vid: str) -> dict:
        with self.lock:
            v = self.mgr.reject(vid)
            return {"ok": True, "state": v.response_state.value}

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "trusted_aps": self.baseline.trusted_aps(),
                "verdicts": [v.to_dict() for v in self.mgr.list()],
                "scenarios": [{"id": k, "label": v[0]} for k, v in SCENARIOS.items()],
                "log": self.events_log[-20:],
                "telegram": telegram.configured(),
                "email": email_alert.configured(),
                "mode": "live" if self.online else "dry-run",
                "verdicts_by_lang": {
                    v.id: {"en": summarize(v, "en"), "hi": summarize(v, "hi")}
                    for v in self.mgr.list()},
            }


class Handler(BaseHTTPRequestHandler):
    state: AppState = None

    def log_message(self, *a):
        pass  # quiet

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json_body(self):
        n = int(self.headers.get("Content-Length", 0))
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode())
        except Exception:
            return {}

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            path = os.path.join(WEB_DIR, "index.html")
            with open(path, "rb") as fh:
                self._send(200, fh.read(), "text/html; charset=utf-8")
        elif self.path == "/api/state":
            self._send(200, json.dumps(self.state.snapshot()))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        body = self._json_body()
        if self.path == "/api/scan":
            self._send(200, json.dumps(self.state.scan(body.get("scenario", "benign"))))
        elif self.path == "/api/approve":
            self._send(200, json.dumps(self.state.approve(body.get("id", ""))))
        elif self.path == "/api/reject":
            self._send(200, json.dumps(self.state.reject(body.get("id", ""))))
        else:
            self._send(404, json.dumps({"error": "not found"}))


def serve(host: str = "127.0.0.1", port: int = 8080, online: bool = False):
    Handler.state = AppState(online=online)
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"AirWarden console on http://{host}:{port}  "
          f"(mode: {'live' if online else 'dry-run'})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--online", action="store_true")
    a = p.parse_args()
    serve(a.host, a.port, a.online)
