"""Alert tests: bilingual formatting, the email subject/body builder, and that
channels no-op cleanly when unconfigured (so nothing breaks without creds)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from airwarden.baseline import Baseline
from airwarden.detect import DetectionEngine
from airwarden.agent import Investigator
from airwarden.alert import email_alert, telegram, send_all, summarize
import make_fixtures as mf


def _a_verdict():
    b = Baseline()
    for ssid, bssid, ch, sec in mf.TRUSTED:
        b.add_trusted(bssid, ssid, ch, sec)
    frames = mf.evil_twin_frames()
    b.record_all(frames)
    ev = DetectionEngine(b).run(frames)[0]
    return Investigator(b, use_llm=False).investigate(ev)


def test_email_build():
    v = _a_verdict()
    subject, body = email_alert.build_message(v)
    assert subject.startswith("[AirWarden]")
    assert "evil_twin" in subject
    assert "EN:" in body and "HI:" in body          # bilingual
    assert "Recommended fix" in body
    print("  email subject:", subject)


def test_channels_off_by_default():
    # with no env creds, both channels are 'off' and send is a safe no-op
    for k in ("AIRWARDEN_SMTP_HOST", "AIRWARDEN_MAIL_TO",
              "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
        os.environ.pop(k, None)
    assert email_alert.configured() is False
    assert telegram.configured() is False
    res = send_all(_a_verdict())
    assert res == {"telegram": None, "email": None}
    print("  unconfigured -> both channels no-op:", res)


def test_email_configured_flag():
    os.environ["AIRWARDEN_SMTP_HOST"] = "smtp.example.com"
    os.environ["AIRWARDEN_MAIL_TO"] = "ops@example.com"
    try:
        assert email_alert.configured() is True
        print("  email configured() True when host+recipient set")
    finally:
        os.environ.pop("AIRWARDEN_SMTP_HOST", None)
        os.environ.pop("AIRWARDEN_MAIL_TO", None)


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        print("•", t.__name__); t()
    print("\n%d/%d alert tests passed" % (len(tests), len(tests)))


if __name__ == "__main__":
    _main()
