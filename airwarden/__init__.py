"""AirWarden — AI-assisted Wi-Fi intrusion detection for small networks.

Pipeline: capture -> detect (rules) -> investigate (agent) -> respond
(approved, verified). The detection core is dependency-free; capture, agent,
response and alerting layers have optional backends (Scapy, LangGraph, SSH,
Telegram) that activate when their dependencies/hardware are present.
"""
__version__ = "0.1.0"
