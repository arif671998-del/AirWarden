"""Agentic investigation layer.

Given a DetectionEvent, the investigator plans which checks to run, executes
them as tools, weighs the evidence into a confidence score, and emits a
Verdict with a recommended (approval-gated) fix.

The investigation engine is dependency-free and works offline, matching the
design principle that detection and triage keep working without network. When
a language model is reachable (hosted API or local Ollama) it is used to write
the plain-language reasoning; otherwise a deterministic explainer is used. When
LangGraph is installed, the same nodes can run as a StateGraph (see graph.py).
"""
from .investigator import Investigator  # noqa: F401
