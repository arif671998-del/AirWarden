"""Telegram delivery (stdlib urllib).

Pushes bilingual verdict summaries to an operator's Telegram chat. Configured
by environment variables; a no-op (returns False) when unconfigured or when the
API is unreachable, so the rest of the system is unaffected.

Env vars:
  TELEGRAM_BOT_TOKEN   bot token from @BotFather
  TELEGRAM_CHAT_ID     target chat/channel id
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Optional

from .format import bilingual
from ..schema import Verdict


def configured() -> bool:
    return bool(os.environ.get("TELEGRAM_BOT_TOKEN")
               and os.environ.get("TELEGRAM_CHAT_ID"))


def send_text(text: str) -> bool:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat = os.environ.get("TELEGRAM_CHAT_ID")
    if not (token and chat):
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": chat, "text": text}).encode()
    try:
        with urllib.request.urlopen(url, data=data, timeout=10) as r:
            out = json.loads(r.read().decode())
            return bool(out.get("ok"))
    except Exception:
        return False


def send_verdict(v: Verdict) -> bool:
    return send_text(bilingual(v))
