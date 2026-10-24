"""Trusted-AP baseline, backed by SQLite (stdlib only).

The baseline records the APs an operator has authorised. Detectors use it to
tell an authorised AP from an impostor: an AP broadcasting a trusted SSID with
a different BSSID/vendor/security fingerprint is a prime evil-twin suspect, and
any BSSID not in the baseline is a rogue-AP candidate.
"""
from __future__ import annotations

import sqlite3
import time
from typing import List, Optional, Dict, Any

from .schema import Frame, Security


OUI_VENDORS = {
    # tiny built-in OUI table; the agent's vendor-lookup tool can extend this
    "00:0c:29": "VMware",
    "dc:a6:32": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "00:50:f2": "Microsoft",
    "f4:f2:6d": "TP-Link",
    "50:c7:bf": "TP-Link",
    "d8:47:32": "TP-Link",
    "00:1a:11": "Google",
    "ac:22:0b": "ASUS",
    "74:da:88": "TP-Link",
}


def vendor_for(bssid: str) -> str:
    return OUI_VENDORS.get(bssid.lower()[:8], "unknown")


SCHEMA = """
CREATE TABLE IF NOT EXISTS trusted_ap (
    bssid TEXT PRIMARY KEY,
    ssid TEXT NOT NULL,
    channel INTEGER,
    vendor TEXT,
    security TEXT,
    pmf INTEGER,
    note TEXT,
    added_ts REAL
);
CREATE TABLE IF NOT EXISTS observation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL, bssid TEXT, ssid TEXT, channel INTEGER,
    security TEXT, rssi INTEGER, ftype TEXT
);
CREATE INDEX IF NOT EXISTS idx_obs_bssid ON observation(bssid);
CREATE INDEX IF NOT EXISTS idx_obs_ssid ON observation(ssid);
"""


class Baseline:
    def __init__(self, path: str = ":memory:"):
        # check_same_thread=False: the HTTP server handles requests on worker
        # threads; callers serialise access (see server AppState.lock).
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # -- trusted APs --------------------------------------------------------
    def add_trusted(self, bssid: str, ssid: str, channel: Optional[int] = None,
                    security: Security = Security.WPA2, pmf: Optional[bool] = None,
                    note: str = "") -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO trusted_ap "
            "(bssid, ssid, channel, vendor, security, pmf, note, added_ts) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (bssid.lower(), ssid, channel, vendor_for(bssid),
             security.value if isinstance(security, Security) else security,
             None if pmf is None else int(pmf), note, time.time()))
        self.conn.commit()

    def learn_from(self, frames: List[Frame]) -> int:
        """Convenience: treat a clean capture as the authorised environment."""
        seen = {}
        for f in frames:
            if f.ftype.value in ("beacon", "probe_resp") and f.ssid:
                seen[f.bssid] = f
        for f in seen.values():
            self.add_trusted(f.bssid, f.ssid, f.channel, f.security, f.pmf,
                             note="learned")
        return len(seen)

    def trusted_aps(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM trusted_ap")]

    def is_trusted_bssid(self, bssid: str) -> bool:
        cur = self.conn.execute("SELECT 1 FROM trusted_ap WHERE bssid=?",
                                (bssid.lower(),))
        return cur.fetchone() is not None

    def trusted_for_ssid(self, ssid: str) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM trusted_ap WHERE ssid=?", (ssid,))]

    def get(self, bssid: str) -> Optional[Dict[str, Any]]:
        r = self.conn.execute("SELECT * FROM trusted_ap WHERE bssid=?",
                              (bssid.lower(),)).fetchone()
        return dict(r) if r else None

    # -- observations (used by the agent for signal/beacon history) ---------
    def record(self, f: Frame) -> None:
        self.conn.execute(
            "INSERT INTO observation (ts,bssid,ssid,channel,security,rssi,ftype)"
            " VALUES (?,?,?,?,?,?,?)",
            (f.ts, f.bssid, f.ssid, f.channel, f.security.value, f.rssi,
             f.ftype.value))

    def record_all(self, frames: List[Frame]) -> None:
        for f in frames:
            self.record(f)
        self.conn.commit()

    def signal_history(self, bssid: str) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.conn.execute(
            "SELECT ts, rssi, channel FROM observation "
            "WHERE bssid=? AND rssi IS NOT NULL ORDER BY ts", (bssid.lower(),))]

    def close(self) -> None:
        self.conn.close()
