"""Integration test for the dashboard API.

Starts the real ThreadingHTTPServer in a background thread and drives it with
HTTP requests from the main thread (a different thread than the request
handlers, so this also exercises cross-thread SQLite access). Covers scan ->
verdicts -> approve -> apply+verify, and the benign (no-alarm) path.
"""
import json
import os
import sys
import threading
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import make_fixtures as mf
from airwarden.server.app import Handler, AppState


def _post(base, path, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data,
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=5).read())


def _get(base, path):
    return json.loads(urllib.request.urlopen(base + path, timeout=5).read())


def main():
    mf.build_all()  # ensure fixtures exist
    Handler.state = AppState()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    base = f"http://127.0.0.1:{port}"
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        st = _get(base, "/api/state")
        assert len(st["trusted_aps"]) == 3, st["trusted_aps"]
        print("• state: %d trusted APs, mode=%s" % (len(st["trusted_aps"]), st["mode"]))

        r = _post(base, "/api/scan", {"scenario": "evil_twin"})
        v = r["verdicts"][0]
        assert v["event"]["attack"] == "evil_twin"
        assert v["fix"]["action"] == "block_bssid"
        print("• scan evil_twin: %s %d%% fix=%s" %
              (v["label"], round(v["confidence"] * 100), v["fix"]["action"]))

        ar = _post(base, "/api/approve", {"id": v["id"]})
        assert ar["ok"] is True
        assert ar["state"] == "verified"
        assert any("macfilter='deny'" in c for c in ar["apply"]["commands"])
        print("• approve: state=%s, %d cmds, verify=%s" %
              (ar["state"], len(ar["apply"]["commands"]), ar["verification"]["note"]))

        r2 = _post(base, "/api/scan", {"scenario": "rogue_ap"})
        ssids = {x["event"]["ssid"] for x in r2["verdicts"]}
        assert "PMWANI_FreeFast" in ssids
        print("• scan rogue_ap: %d verdicts incl PMWANI" % len(r2["verdicts"]))

        r3 = _post(base, "/api/scan", {"scenario": "benign"})
        assert r3["verdicts"] == []
        print("• scan benign: 0 verdicts (clean)")

        print("\nserver integration OK")
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    main()
