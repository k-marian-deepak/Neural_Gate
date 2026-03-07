from __future__ import annotations

from app.agents.cnn_model import InferenceModel


class HeaderAgent:
    def __init__(self, model: InferenceModel) -> None:
        self.model = model

    def score(self, headers: dict[str, str], path: str) -> float:
        content = "\n".join([f"{k}:{v}" for k, v in headers.items()]) + path
        return self.model.predict(content.encode("utf-8", errors="ignore"))
