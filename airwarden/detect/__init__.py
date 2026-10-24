"""Rule-based detectors. Each takes (frames, baseline, config) and returns
DetectionEvents with frame-referenced evidence. Detection runs fully offline;
only the later agent stage may call a language model."""
from .engine import DetectionEngine, DetectorConfig  # noqa: F401
