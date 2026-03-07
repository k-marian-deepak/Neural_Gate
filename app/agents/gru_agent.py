from __future__ import annotations

from collections import defaultdict, deque


class GRUTemporalAgent:
    def __init__(self, max_history: int = 20) -> None:
        self._history: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=max_history))

    def score(self, source_ip: str, current_score: float) -> float:
        history = self._history[source_ip]
        history.append(current_score)
        if not history:
            return current_score
        rolling = sum(history) / len(history)
        return float(min(max((current_score * 0.7) + (rolling * 0.3), 0.0), 1.0))
