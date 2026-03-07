from __future__ import annotations

import numpy as np

try:
    import torch
    import torch.nn as nn
except Exception:  # pragma: no cover
    torch = None
    nn = None


class NeuralGateCNN(nn.Module if nn else object):
    def __init__(self) -> None:
        if not nn:
            return
        super().__init__()
        self.conv = nn.Sequential(
            nn.Conv1d(1, 32, kernel_size=8),
            nn.ReLU(),
            nn.MaxPool1d(4),
            nn.Conv1d(32, 64, kernel_size=4),
            nn.ReLU(),
            nn.MaxPool1d(4),
            nn.Conv1d(64, 128, kernel_size=3),
            nn.ReLU(),
            nn.AdaptiveAvgPool1d(32),
        )
        self.gru = nn.GRU(input_size=128, hidden_size=64, num_layers=2, bidirectional=True, batch_first=True)
        self.drop = nn.Dropout(0.4)
        self.out = nn.Linear(64 * 2, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        x = self.conv(x)
        x = x.transpose(1, 2)
        _, hidden = self.gru(x)
        hidden = torch.cat((hidden[-2], hidden[-1]), dim=1)
        hidden = self.drop(hidden)
        return self.sigmoid(self.out(hidden))


class InferenceModel:
    def __init__(self, model_path: str) -> None:
        self.model_path = model_path
        self.model = None
        self._load()

    def _load(self) -> None:
        if not torch:
            return
        model = NeuralGateCNN()
        try:
            state = torch.load(self.model_path, map_location="cpu")
            model.load_state_dict(state)
            model.eval()
            self.model = model
        except Exception:
            self.model = None

    def predict(self, payload: bytes) -> float:
        if self.model is None or not torch:
            if not payload:
                return 0.0
            entropy_proxy = len(set(payload[:512])) / min(len(payload[:512]), 256)
            return float(min(max(entropy_proxy, 0.0), 1.0))

        arr = np.frombuffer(payload[:1024].ljust(1024, b"\x00"), dtype=np.uint8).astype(np.float32) / 255.0
        tensor = torch.tensor(arr).view(1, 1, 1024)
        with torch.no_grad():
            score = self.model(tensor).item()
        return float(min(max(score, 0.0), 1.0))
