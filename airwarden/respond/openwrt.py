"""OpenWrt response actions via UCI over SSH.

Each AirWarden fix maps to a short, reversible sequence of UCI commands run on
the operator's own router. SSH uses the system `ssh` client (stdlib subprocess),
so no third-party package is needed. In dry-run mode (the default) the commands
are recorded but not executed — safe for demos and for review before approval.
"""
from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass, field
from typing import List

from ..schema import RecommendedFix


@dataclass
class ResponseResult:
    ok: bool
    commands: List[str] = field(default_factory=list)
    output: str = ""
    dry_run: bool = True

    def to_dict(self):
        return {"ok": self.ok, "commands": self.commands,
                "output": self.output, "dry_run": self.dry_run}


class OpenWrtRouter:
    def __init__(self, host: str = "192.168.1.1", user: str = "root",
                 iface: str = "default_radio0", dry_run: bool = True,
                 ssh_opts: str = "-o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new"):
        self.host = host
        self.user = user
        self.iface = iface
        self.dry_run = dry_run
        self.ssh_opts = ssh_opts

    # -- command builders ---------------------------------------------------
    def _commands_for(self, fix: RecommendedFix) -> List[str]:
        if fix.action == "enable_pmf":
            return [
                f"uci set wireless.{self.iface}.ieee80211w='2'",
                "uci commit wireless",
                "wifi reload",
            ]
        if fix.action == "block_bssid":
            bssid = fix.params.get("bssid", "")
            return [
                f"uci set wireless.{self.iface}.macfilter='deny'",
                f"uci add_list wireless.{self.iface}.maclist='{bssid}'",
                "uci commit wireless",
                "wifi reload",
            ]
        if fix.action == "notify_and_blocklist":
            bssid = fix.params.get("bssid", "")
            return [f"logger -t airwarden 'unauthorised AP {bssid} flagged for review'"]
        return [f"logger -t airwarden 'no automated action for {fix.action}'"]

    def _rollback_for(self, fix: RecommendedFix) -> List[str]:
        if fix.action == "enable_pmf":
            return [f"uci set wireless.{self.iface}.ieee80211w='0'",
                    "uci commit wireless", "wifi reload"]
        if fix.action == "block_bssid":
            bssid = fix.params.get("bssid", "")
            return [f"uci del_list wireless.{self.iface}.maclist='{bssid}'",
                    "uci commit wireless", "wifi reload"]
        return []

    # -- execution ----------------------------------------------------------
    def _run_ssh(self, commands: List[str]) -> ResponseResult:
        joined = " && ".join(commands)
        if self.dry_run:
            return ResponseResult(ok=True, commands=commands,
                                  output="[dry-run] not executed", dry_run=True)
        ssh = f"ssh {self.ssh_opts} {self.user}@{self.host} {shlex.quote(joined)}"
        try:
            p = subprocess.run(ssh, shell=True, capture_output=True, text=True,
                               timeout=30)
            return ResponseResult(ok=(p.returncode == 0), commands=commands,
                                  output=(p.stdout + p.stderr).strip(),
                                  dry_run=False)
        except Exception as ex:
            return ResponseResult(ok=False, commands=commands,
                                  output=f"ssh error: {ex}", dry_run=False)

    def apply(self, fix: RecommendedFix) -> ResponseResult:
        return self._run_ssh(self._commands_for(fix))

    def rollback(self, fix: RecommendedFix) -> ResponseResult:
        cmds = self._rollback_for(fix)
        if not cmds:
            return ResponseResult(ok=True, commands=[], output="nothing to roll back")
        return self._run_ssh(cmds)
