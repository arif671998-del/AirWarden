# AirWarden

**AI-assisted Wi-Fi intrusion detection and response for small networks.**
ChronoForge 2026 · Track: Cybersecurity · Team Vidyut

Wi-Fi attacks that steal logins in minutes go unnoticed on most small networks,
because catching them needs radio-level monitoring *plus* an analyst — and
campuses, hostels, PM-WANI hotspots, cafés and clinics have neither. AirWarden
pairs a low-cost Wi-Fi sensor with an AI agent that investigates each alert,
names the attack **with evidence**, and proposes a fix the operator approves —
then re-checks that it worked.

## What it detects

| Attack | How | Severity logic |
|---|---|---|
| **Deauth / disassoc flood** | burst of spoofed management frames in a sliding window | HIGH when it targets a trusted AP at high rate |
| **Evil twin** (cloned SSID) | trusted SSID broadcast by an unauthorised BSSID | HIGH on security downgrade / PMWANI branding |
| **Rogue AP** | unknown BSSID advertising a new SSID | HIGH if it abuses PMWANI branding |

Every verdict cites the captured frames behind it. **Weak evidence is labelled
`needs_review`, never auto-reported as an attack**, and **no fix touches the
network without operator approval** — then a re-scan verifies it.

## Architecture

```
 capture            detect (rules)        investigate (agent)       respond
 ┌─────────┐        ┌───────────────┐     ┌──────────────────┐     ┌──────────────┐
 │ pcap /  │ Frame  │ deauth        │ evt │ plan → gather →   │ fix │ approve →    │
 │ monitor │──────▶ │ eviltwin      │────▶│ assess → recommend│────▶│ apply (SSH) →│
 │ mode    │        │ rogue         │     │ → explain (LLM?)  │     │ verify       │
 └─────────┘        └───────────────┘     └──────────────────┘     └──────────────┘
      │                     │                      │                       │
   802.11            SQLite baseline        confidence + evidence    OpenWrt UCI/ubus
```

The **detection core is dependency-free** (Python stdlib only). Capture, agent
reasoning, response and alerting have optional backends (Scapy, LangGraph, SSH,
LLM, Telegram) that light up when their dependencies/hardware are present — so
the system runs and demos anywhere, and keeps working offline.

## Quick start (no installs needed)

```bash
# build the demo captures (synthetic, offline test data)
python3 tests/make_fixtures.py

# learn a baseline from clean traffic, then analyse an attack capture
python3 -m airwarden analyze tests/fixtures/evil_twin.pcap \
        --learn tests/fixtures/benign.pcap --no-llm

# run the test suite
python3 tests/test_detect.py && python3 tests/test_agent.py
```

The `.pcap` fixtures are standard radiotap/802.11 and open in Wireshark.

## Safety & responsible use (ChronoForge rules 159–160)

- Monitoring is **passive**; only management-frame metadata is handled, never
  user traffic.
- AirWarden **never transmits attack frames** and never sends counter-deauth.
  The fixture generator writes frames to files only — no radio is touched.
- Responses run **only on the operator's own router, only after approval**.
- Attack simulation, if used on hardware, is confined to the team's own lab.

## How it maps to the judging criteria

- **Technical implementation / rigor:** real 802.11 parsing, RSN/PMF analysis,
  evidence-linked detection, a planning agent with confidence scoring.
- **Functionality:** end-to-end pipeline with a passing test suite and a CLI.
- **Innovation:** closes the loop — investigate → approve → verify — where
  alert-only tools (Kismet, vendor WIPS consoles) stop at the alert.
- **Impact / track alignment:** built for Indian public Wi-Fi (PMWANI), runs on
  a Raspberry Pi, Hindi + English alerts.

## Layout

```
airwarden/
  schema.py       shared types (Frame, DetectionEvent, Verdict)
  pcap.py         stdlib pcap + radiotap + 802.11 codec
  baseline.py     SQLite trusted-AP store
  detect/         deauth, eviltwin, rogue + engine
  agent/          investigator (nodes), tools, llm, langgraph wrapper
  cli.py          `python3 -m airwarden`
tests/            fixtures generator + detector/agent tests
```
