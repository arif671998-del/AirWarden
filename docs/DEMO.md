# AirWarden — 3-minute demo script

Runs entirely on recorded captures, no Wi-Fi hardware needed. One laptop.

## Setup (once, before judging)

```bash
git clone https://github.com/arif671998-del/airwarden && cd airwarden
python3 tests/make_fixtures.py          # build the demo captures
python3 -m airwarden.server.app         # starts http://127.0.0.1:8080
```
Open `http://127.0.0.1:8080` in a browser. (Optional: `export
TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=...` before starting to show live
Telegram alerts; optional `AIRWARDEN_LLM=ollama` for LLM-written reasoning.)

Keep a Wireshark window open on `tests/fixtures/evil_twin.pcap` as a prop —
it shows the captures are real 802.11.

## The script

**0:00 — The problem (spoken, dashboard open).**
"Small networks — campuses, hostels, PM-WANI hotspots, cafés — get hit by
Wi-Fi attacks that steal logins in minutes, and nobody notices because
catching them needs both radio monitoring and an analyst. AirWarden is that
analyst. It runs on a Raspberry Pi."

**0:25 — Baseline.** Point to the left panel. "These three are the authorised
access points. Anything that doesn't match is a suspect."

**0:40 — Evil twin.** Select **Evil twin → Run scan**. A CONFIRMED card appears
at 90%. "It found an access point broadcasting 'CampusWiFi' — but from an
unauthorised radio, and it's OPEN while the real one is WPA2. That's a fake
login portal pattern." Expand **Evidence & investigation**: "Every verdict
cites the frames behind it, and these are the checks the agent ran itself —
baseline, beacon comparison, vendor, signal, portal."

**1:30 — Closing the loop.** "Alert-only tools stop here. AirWarden proposes a
fix." Click **Approve & apply**. Show the UCI commands and the green
**verified** state. "It applied the fix on the operator's own router — in
dry-run here — then re-scanned and confirmed the attack is gone. Nothing
touches the network without approval."

**2:10 — Deauth + PMWANI.** Run **Deauth flood** (CONFIRMED 98% → enable
802.11w) and **Rogue + PMWANI AP** (the PMWANI-branded impostor is HIGH).
"Built for Indian public Wi-Fi: an unknown AP using PMWANI branding is flagged
immediately." Expand **Operator alert** to show the Hindi + English summary.

**2:40 — No false alarms.** Run **Normal traffic**: zero events. "On clean
traffic it stays quiet — weak evidence is marked needs-review, never cried
wolf as an attack."

**2:55 — Close.** "Detection runs offline on a Pi; only the reasoning calls a
model, and even that falls back to a local one. Passive monitoring, management
frames only, every response approved and verified."

## If asked

- **Live capture?** `capture/live.py` puts a monitor-mode adapter into the same
  `Frame` stream via Scapy; the demo uses recordings for reliability.
- **Why not transmit test attacks?** Responsible-use rule: AirWarden never
  transmits attack frames. Fixtures are crafted offline and written to pcap.
- **Scale?** Many sensors → one central agent; new attacks = a detector + agent
  tool; the sensor can later run on the OpenWrt router itself.
