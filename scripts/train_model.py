from __future__ import annotations

from pathlib import Path
import sys

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.agents.cnn_model import NeuralGateCNN


def build_dataset(samples: int = 2000):
    benign = np.random.normal(loc=0.35, scale=0.08, size=(samples // 2, 1024)).clip(0, 1)
    malicious = np.random.normal(loc=0.75, scale=0.15, size=(samples // 2, 1024)).clip(0, 1)

    x = np.concatenate([benign, malicious], axis=0).astype(np.float32)
    y = np.concatenate([np.zeros((samples // 2, 1)), np.ones((samples // 2, 1))], axis=0).astype(np.float32)

    idx = np.random.permutation(samples)
    x = x[idx]
    y = y[idx]

    x_tensor = torch.tensor(x).unsqueeze(1)
    y_tensor = torch.tensor(y)
    return TensorDataset(x_tensor, y_tensor)


def train() -> None:
    torch.manual_seed(42)
    np.random.seed(42)

    dataset = build_dataset()
    loader = DataLoader(dataset, batch_size=64, shuffle=True)

    model = NeuralGateCNN()
    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

    model.train()
    for _ in range(3):
        for batch_x, batch_y in loader:
            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()

    model_dir = Path("app/models")
    model_dir.mkdir(parents=True, exist_ok=True)
    output = model_dir / "neural_gate_cnn.pt"
    torch.save(model.state_dict(), output)
    print(f"Model saved to {output}")


if __name__ == "__main__":
    train()
