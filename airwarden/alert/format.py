"""Plain-language alert summaries in English and Hindi.

Operators of small networks are not analysts, so AirWarden translates each
verdict into one or two clear sentences: what happened, and what the proposed
fix does. Hindi is provided because the target users include PM-WANI operators
and campus/café staff across India.
"""
from __future__ import annotations

from ..schema import Verdict, AttackType, VerdictLabel

_EN = {
    AttackType.DEAUTH_FLOOD: (
        "Attack detected: a deauthentication flood is repeatedly knocking "
        "devices off '{ssid}'. Suggested fix: turn on 802.11w (Protected "
        "Management Frames) on your router so forged disconnects are rejected."),
    AttackType.EVIL_TWIN: (
        "Warning: a fake copy of '{ssid}' is broadcasting nearby (impostor "
        "{bssid}). Do not type your password on it. Suggested fix: block the "
        "impostor and warn users."),
    AttackType.ROGUE_AP: (
        "Notice: an unauthorised access point '{ssid}' ({bssid}) is "
        "broadcasting near your network. Review whether it should be there."),
}

_HI = {
    AttackType.DEAUTH_FLOOD: (
        "हमला पाया गया: '{ssid}' नेटवर्क से डिवाइसों को बार-बार डिस्कनेक्ट करने वाला "
        "deauth flood हमला हो रहा है। सुझाया गया समाधान: राउटर पर 802.11w (PMF) "
        "चालू करें ताकि नकली डिस्कनेक्ट रिक्वेस्ट अस्वीकार हों।"),
    AttackType.EVIL_TWIN: (
        "चेतावनी: '{ssid}' की एक नकली कॉपी आसपास चल रही है (नकली {bssid})। उस पर "
        "अपना पासवर्ड न डालें। सुझाव: नकली AP को ब्लॉक करें और उपयोगकर्ताओं को सूचित करें।"),
    AttackType.ROGUE_AP: (
        "सूचना: आपके नेटवर्क के पास एक अनधिकृत एक्सेस पॉइंट '{ssid}' ({bssid}) चल रहा है। "
        "जाँचें कि यह अधिकृत है या नहीं।"),
}

_REVIEW_EN = ("Possible issue needs review: {summary}. Evidence is not yet "
              "conclusive, so no action is proposed.")
_REVIEW_HI = ("संभावित समस्या की समीक्षा आवश्यक: {summary}. प्रमाण अभी निर्णायक नहीं हैं, "
              "इसलिए कोई कार्रवाई प्रस्तावित नहीं है।")


def summarize(v: Verdict, lang: str = "en") -> str:
    e = v.event
    ssid = e.ssid or (v.fix.params.get("ssid") if v.fix else "") or e.bssid
    table = _HI if lang == "hi" else _EN
    if v.label == VerdictLabel.NEEDS_REVIEW:
        tmpl = _REVIEW_HI if lang == "hi" else _REVIEW_EN
        return tmpl.format(summary=e.summary)
    tmpl = table.get(e.attack)
    if not tmpl:
        return e.summary
    return tmpl.format(ssid=ssid, bssid=e.bssid)


def bilingual(v: Verdict) -> str:
    label = v.label.value.replace("_", " ").upper()
    head = f"[{label} · {v.confidence:.0%}]"
    return f"{head}\nEN: {summarize(v, 'en')}\nHI: {summarize(v, 'hi')}"
