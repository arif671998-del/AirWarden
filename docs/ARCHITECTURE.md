# AirWarden architecture

## Pipeline

```
 ┌──────────┐   Frame[]   ┌──────────────┐  DetectionEvent[]  ┌───────────────┐
 │ capture  │ ──────────▶ │ detect       │ ─────────────────▶ │ agent         │
 │          │             │ (rules)      │                    │ (investigate) │
 │ replay / │             │ deauth       │                    │ plan→gather→  │
 │ live     │             │ eviltwin     │                    │ assess→       │
 └──────────┘             │ rogue        │                    │ recommend→    │
      ▲                   └──────────────┘                    │ explain       │
      │                          │                            └───────┬───────┘
 802.11 frames            SQLite baseline                     Verdict │ (+fix)
 (pcap or monitor)        (trusted APs)                               ▼
                                                            ┌────────────────────┐
                                     dashboard / Telegram ◀─│ respond            │
                                     (approve / reject)     │ approval → OpenWrt │
                                                            │ apply → verify     │
                                                            └────────────────────┘
```

Everything speaks `schema.Frame`, `DetectionEvent`, `Verdict` (see
`airwarden/schema.py`), so each stage is independently testable and
replaceable.

## Modules

| Module | Responsibility | Deps |
|---|---|---|
| `pcap.py` | pcap + radiotap + 802.11 encode/decode | stdlib |
| `capture/replay.py` | recorded captures → Frame | stdlib |
| `capture/live.py` | monitor-mode capture → Frame | Scapy (lazy) |
| `baseline.py` | trusted-AP store, OUI vendor, signal history | stdlib (sqlite3) |
| `detect/*` | rule detectors + engine | stdlib |
| `agent/investigator.py` | plan/gather/assess/recommend/explain | stdlib |
| `agent/graph.py` | same nodes as a LangGraph StateGraph | LangGraph (lazy) |
| `agent/llm.py` | optional reasoning narration | stdlib urllib |
| `respond/openwrt.py` | UCI-over-SSH actions, dry-run, rollback | stdlib |
| `respond/approval.py` | approval + re-scan verification state machine | stdlib |
| `alert/*` | EN/HI summaries, Telegram push | stdlib urllib |
| `server/app.py` | dashboard + JSON API | stdlib http.server |

## Key design decisions

1. **Dependency-free core.** Detection, triage and response run on a stock
   Python install. Optional backends (Scapy, LangGraph, an LLM, Telegram) light
   up when present but are never required — so the system demos anywhere and
   keeps working offline, matching the proposal's offline-first principle.

2. **Evidence-first.** Every detection carries `Evidence` objects with frame
   references; the agent adds its own. A verdict can always be traced back to
   the frames that justify it. Weak evidence → `needs_review`, never reported as
   an attack.

3. **The agent is deterministic; the LLM only narrates.** Classification and
   confidence come from auditable rules and tool results, so verdicts are
   reproducible. An LLM (if configured) rewrites the explanation for operators
   but cannot change the verdict.

4. **Human-in-the-loop response.** No network change without operator approval.
   Actions are reversible (`rollback`) and every applied fix is re-scanned to
   confirm it worked. Dry-run is the default.

5. **Responsible by construction.** Passive monitoring, management-frame
   metadata only. AirWarden never transmits attack frames; test "attacks" are
   crafted offline and written to pcap, never to a radio.

## Extending it

- **New attack:** add a detector under `detect/` (emit `DetectionEvent` with
  evidence), register it in `engine.py`, and add a tool + plan entry in
  `agent/`.
- **New response:** add a command builder in `respond/openwrt.py` and a branch
  in `investigator._recommend`.
- **New sensor:** anything that yields `schema.Frame` plugs into the pipeline.
