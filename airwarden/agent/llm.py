"""Optional LLM adapter for plain-language reasoning.

Used only to narrate a verdict the deterministic engine already decided; it
never changes the classification or confidence. Supports an OpenAI-compatible
chat endpoint or a local Ollama server, configured by environment variables.
Falls back to None (so the caller uses its deterministic explanation) whenever
no backend is configured or the call fails — the system keeps working offline.

Env vars:
  AIRWARDEN_LLM=openai|ollama|none   (default: none)
  OPENAI_BASE_URL, OPENAI_API_KEY, OPENAI_MODEL
  OLLAMA_BASE_URL (default http://localhost:11434), OLLAMA_MODEL
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import List, Optional

_SYS = ("You are AirWarden's security analyst. In 2-3 sentences, explain the "
        "verdict to a non-expert network operator: what was detected, why it is "
        "or isn't an attack, and what the recommended fix does. Be precise and "
        "do not invent evidence beyond what is given.")


def _prompt(event: dict, label: str, conf: float, facts: List[str]) -> str:
    return (f"Attack type: {event.get('attack')}\n"
            f"BSSID: {event.get('bssid')}  SSID: {event.get('ssid')}\n"
            f"Verdict: {label} (confidence {conf:.0%})\n"
            f"Evidence:\n- " + "\n- ".join(facts))


def explain(event: dict, label: str, conf: float, facts: List[str]) -> Optional[str]:
    backend = os.environ.get("AIRWARDEN_LLM", "none").lower()
    try:
        if backend == "openai":
            return _openai(event, label, conf, facts)
        if backend == "ollama":
            return _ollama(event, label, conf, facts)
    except Exception:
        return None  # any failure -> deterministic fallback upstream
    return None


def _http_json(url: str, payload: dict, headers: dict, timeout: int = 20) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _openai(event, label, conf, facts) -> Optional[str]:
    base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    key = os.environ.get("OPENAI_API_KEY")
    model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    if not key:
        return None
    out = _http_json(
        f"{base}/chat/completions",
        {"model": model, "temperature": 0.2,
         "messages": [{"role": "system", "content": _SYS},
                      {"role": "user", "content": _prompt(event, label, conf, facts)}]},
        {"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    return out["choices"][0]["message"]["content"].strip()


def _ollama(event, label, conf, facts) -> Optional[str]:
    base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    model = os.environ.get("OLLAMA_MODEL", "llama3.1")
    out = _http_json(
        f"{base}/api/chat",
        {"model": model, "stream": False,
         "messages": [{"role": "system", "content": _SYS},
                      {"role": "user", "content": _prompt(event, label, conf, facts)}]},
        {"Content-Type": "application/json"})
    return out["message"]["content"].strip()
