from __future__ import annotations

from app.agents.cnn_model import InferenceModel
from app.config import settings


class EgressAgent:
    def __init__(self, model: InferenceModel) -> None:
        self.model = model

    def score(self, body: bytes, entropy: float) -> float:
        model_score = self.model.predict(body)
        entropy_score = min(max(entropy / max(settings.exfiltration_entropy_threshold, 0.1), 0.0), 1.0)
        return float((model_score * 0.7) + (entropy_score * 0.3))
