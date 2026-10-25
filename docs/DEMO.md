# AirWarden — demo script (8 attacks)

Runs entirely on recorded captures, no Wi-Fi hardware needed. One laptop,
~4–5 minutes. Passive and lab-safe: nothing is ever transmitted.

## Setup (before judging)

```bash
git clone https://github.com/arif671998-del/airwarden && cd airwarden
python3 tests/make_fixtures.py          # build the demo captures
python3 tests/run_all.py                # optional: show all tests green
python3 -m airwarden.server.app         # http://127.0.0.1:8080
```
Open `http://127.0.0.1:8080`. Optional extras, set *before* starting the server:
`export AIRWARDEN_LLM=ollama` (AI-written reasoning), Telegram or email env vars
(live alerts — the pills up top turn green). Keep Wireshark open on
`tests/fixtures/evil_twin.pcap` as a prop: the captures are real 802.11.

## The flow

**0:00 — Problem.** "Small networks — campuses, hostels, PM-WANI hotspots,
cafés — get hit by Wi-Fi attacks that steal logins in minutes, and nobody
notices, because catching them needs radio monitoring *and* a security analyst.
AirWarden is that analyst, on a Raspberry Pi."

**0:30 — Baseline.** Point to the left panel. "These three APs are authorised.
Anything else is a suspect."

**0:45 — Evil twin (the investigation showcase).** Select **Evil twin → Run
scan** → CONFIRMED 90%. Expand **Evidence & investigation**: "It cloned
'CampusWiFi' from an unauthorised radio, and it's OPEN while the real one is
WPA2 — a fake-portal pattern. Every verdict cites the frames, and these are the
checks the agent ran *itself*: baseline, beacon comparison, vendor, signal,
portal."

**1:30 — Closing the loop.** Click **Approve & apply**. Show the UCI commands
and the green **verified** badge. "Alert-only tools stop at the alert.
AirWarden proposes a fix on the operator's own router, applies it only after
approval — in dry-run here — then re-scans to confirm it worked."

**2:15 — Typosquat (the clever one).** Run **SSID typosquat** → CONFIRMED 80%.
"Subtler evil twin: 'Campus-WiFi' instead of 'CampusWiFi'. We catch look-alikes
by homoglyph and edit-distance matching against the baseline — the branding
trick that fools users."

**2:45 — Breadth sweep (one line each).** Run these in turn:
- **Deauth flood** → 98%, fix: enable 802.11w.
- **Karma / MANA** → one AP answering probes for 6 different networks.
- **Beacon flood** → 24 fake APs in 3s.
- **Auth / assoc flood** → table-exhaustion attack on CampusWiFi.
- **MAC spoofing** → "two radios share one BSSID — we catch it from
  sequence-number jumps. Note the fix is **advisory, not a block**: blocking
  that MAC would also kill the real AP. The tool knows the difference."

**3:45 — No false alarms.** Run **Normal traffic** → zero events. "On clean
traffic it stays quiet. Weak evidence is marked needs-review, never cried wolf."

**4:00 — Close.** "Eight attack classes, each with evidence, a confidence
score, and an approved, verified response. Detection runs offline on a Pi;
alerts go to a dashboard, Telegram, or email in English and Hindi. Passive
monitoring, management frames only, never transmits an attack — built for
Indian public Wi-Fi, PMWANI included."

## Q&A prep (questions judges actually ask)

- **How does the sensor see a standalone rogue AP?** Passive monitor mode —
  every AP beacons ~10×/sec to anyone in range, connected or not. We listen;
  the AP betrays itself. Range is per-sensor, so a campus uses several sensors
  into one agent. A monitor card hears one channel at a time, so it hops 1/6/11.
- **Who makes the authorised list?** The operator — by hand for a small site
  (they know their own APs), or learn-and-confirm for a campus. A new unknown AP
  becomes a one-click "add to baseline". (It's trust-on-first-use, like SSH.)
- **Why not demo live attacks?** Deauth/evil-twin transmit frames that hit every
  device in range — not a lab. We simulate with recorded captures instead;
  responsible-use is a design rule, not an afterthought.

## Future work (the scalability slide)

- More detectors: KRACK handshake replay, WPS brute-force, RTS/CTS virtual
  jamming.
- Multi-sensor mesh reporting to one central agent (campus-scale).
- Sensor running directly on the OpenWrt router.
- New attacks plug in as a detector + an agent tool — the architecture is built
  for it (8 detectors today, all behind one `Frame` interface).
