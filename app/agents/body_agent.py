from __future__ import annotations

from app.agents.cnn_model import InferenceModel


class BodyAgent:
    def __init__(self, model: InferenceModel) -> None:
        self.model = model

    def score(self, body: bytes) -> float:
        return self.model.predict(body)
