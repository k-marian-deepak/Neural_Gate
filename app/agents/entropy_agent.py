from __future__ import annotations

from app.config import settings


class EntropyAgent:
    def score(self, entropy: float) -> float:
        normalized = entropy / max(settings.exfiltration_entropy_threshold, 0.1)
        return float(min(max(normalized, 0.0), 1.0))
