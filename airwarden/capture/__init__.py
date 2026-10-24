"""Capture layer: turns a source of 802.11 frames into schema.Frame objects.

Two backends, same output:
  - replay.py  : read recorded .pcap files (dependency-free; used for tests,
                 the demo, and the API/4 lab fallback).
  - live.py    : monitor-mode capture on real hardware via Scapy (optional;
                 imported only when used, so Scapy is not a hard dependency).
"""
from .replay import replay_pcap, iter_pcap  # noqa: F401
