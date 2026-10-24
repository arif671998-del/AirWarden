"""Operator-facing alerting: plain-language (English + Hindi) summaries and
delivery channels (dashboard feed, Telegram, email).

`send_all` dispatches a verdict to every configured channel; each channel
no-ops when it isn't configured, so callers don't need to check."""
from typing import Dict, Optional

from .format import summarize, bilingual  # noqa: F401
from . import telegram, email_alert
from ..schema import Verdict


def channels_status() -> Dict[str, bool]:
    return {"telegram": telegram.configured(), "email": email_alert.configured()}


def send_all(v: Verdict) -> Dict[str, Optional[bool]]:
    """Send to each configured channel; value is True/False sent, None if off."""
    return {
        "telegram": telegram.send_verdict(v) if telegram.configured() else None,
        "email": email_alert.send_verdict(v) if email_alert.configured() else None,
    }
