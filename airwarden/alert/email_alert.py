"""Email alerting via SMTP (stdlib smtplib + email).

Sends a verdict to an operator's inbox. Configured by environment variables;
a no-op (returns False) when unconfigured or when sending fails, so the rest of
the system is unaffected.

Env vars:
  AIRWARDEN_SMTP_HOST      e.g. smtp.gmail.com
  AIRWARDEN_SMTP_PORT      default 587 (STARTTLS); 465 uses SSL
  AIRWARDEN_SMTP_USER      SMTP login (often the From address)
  AIRWARDEN_SMTP_PASS      SMTP password / app-password
  AIRWARDEN_MAIL_FROM      sender (defaults to SMTP_USER)
  AIRWARDEN_MAIL_TO        recipient(s), comma-separated
  AIRWARDEN_SMTP_SSL       "1" to force SSL instead of STARTTLS
"""
from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Tuple

from .format import bilingual
from ..schema import Verdict


def configured() -> bool:
    return bool(os.environ.get("AIRWARDEN_SMTP_HOST")
               and os.environ.get("AIRWARDEN_MAIL_TO"))


def build_message(v: Verdict) -> Tuple[str, str]:
    """Return (subject, body) for a verdict — pure, so it's easy to test."""
    e = v.event
    subject = (f"[AirWarden] {v.label.value.upper()} — "
               f"{e.attack.value} ({v.confidence:.0%})")
    body = bilingual(v)
    if v.fix:
        body += f"\n\nRecommended fix (needs approval):\n{v.fix.description}"
    body += "\n\n-- AirWarden Wi-Fi intrusion detection"
    return subject, body


def send_text(subject: str, body: str) -> bool:
    host = os.environ.get("AIRWARDEN_SMTP_HOST")
    to = os.environ.get("AIRWARDEN_MAIL_TO")
    if not (host and to):
        return False
    port = int(os.environ.get("AIRWARDEN_SMTP_PORT", "587"))
    user = os.environ.get("AIRWARDEN_SMTP_USER")
    pw = os.environ.get("AIRWARDEN_SMTP_PASS")
    sender = os.environ.get("AIRWARDEN_MAIL_FROM", user or "airwarden@localhost")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to
    msg.set_content(body)
    use_ssl = os.environ.get("AIRWARDEN_SMTP_SSL") == "1" or port == 465
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=ctx, timeout=15) as s:
                if user:
                    s.login(user, pw)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as s:
                s.starttls(context=ssl.create_default_context())
                if user:
                    s.login(user, pw)
                s.send_message(msg)
        return True
    except Exception:
        return False


def send_verdict(v: Verdict) -> bool:
    subject, body = build_message(v)
    return send_text(subject, body)
