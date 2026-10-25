# AirWarden — 2–3 minute demo video script

Target length **~2:40**. Screen recording of the dashboard, voiceover. Runs on
recorded captures — no hardware, nothing transmitted.

## Before you record

- `python3 tests/make_fixtures.py` then `python3 -m airwarden.server.app`
- Open `http://127.0.0.1:8080`, browser zoomed so text is readable (~110%)
- Do one warm-up scan of each scenario first (so cards render instantly on tape)
- Record at 1280×800 or 1080p. Speak over the clicks; keep a steady pace.

## Script (timed)

**0:00–0:20 — Hook + what it is.**
> "On small networks — campuses, hostels, public hotspots, cafés — Wi-Fi attacks
> steal logins in minutes and nobody notices, because catching them needs radio
> monitoring *and* a security analyst. AirWarden is that analyst, on a Raspberry
> Pi. It detects the attack, investigates it, and fixes it — with the operator's
> approval."
*(On screen: the dashboard, baseline panel visible.)*

**0:20–0:30 — Baseline.**
> "These three access points are authorised. Anything else is a suspect."
*(Point cursor at the Authorised baseline panel.)*

**0:30–1:10 — Evil twin (the core story).**
> "Watch an evil twin." *(Click Evil twin → Run scan.)* "Confirmed, 90%. It
> cloned 'CampusWiFi' from an unauthorised radio, and it's open while the real
> one is WPA2 — a fake login portal."
*(Expand Evidence & investigation.)*
> "Every verdict cites the frames, and these are the checks the agent ran itself
> — baseline, beacon comparison, vendor, signal, portal. Now the part other
> tools skip." *(Click Approve & apply.)* "It applies a fix on the operator's
> own router — in dry-run here — then re-scans and confirms the attack is gone.
> Verified. Nothing changes without approval."

**1:10–1:35 — Typosquat.**
> *(Click SSID typosquat → Run scan.)* "A subtler twin: 'Campus-WiFi' instead of
> 'CampusWiFi'. We catch look-alikes by homoglyph and edit-distance matching —
> the trick that fools real users."

**1:35–2:05 — Breadth (fast).**
> *(Click through, ~5s each.)* "Deauth flood — enable 802.11w. Karma — one AP
> impersonating six networks. Beacon flood — twenty-four fake APs in three
> seconds. Auth flood — table exhaustion. And MAC spoofing — two radios sharing
> one BSSID, caught from sequence-number jumps. Notice its fix is advisory, not
> a block, because blocking that MAC would kill the real AP too. Eight attack
> classes."

**2:05–2:20 — No false alarms.**
> *(Click Normal traffic → Run scan.)* "On clean traffic — zero events. It never
> cries wolf."

**2:20–2:40 — Close.**
> "Detection runs offline on a Pi; alerts reach a dashboard, email, and Telegram
> in English and Hindi. Passive monitoring, never transmits an attack, every fix
> approved and verified — built for Indian public Wi-Fi, PMWANI included.
> That's AirWarden."
*(End on the dashboard or a title card with the GitHub link.)*

## Tips

- If live LLM reasoning is on (`AIRWARDEN_LLM=ollama`), the verdict text reads
  more naturally on camera — optional.
- Trim dead air between clicks in editing to stay under 3:00.
- Add captions for the attack names — judges may watch muted.
