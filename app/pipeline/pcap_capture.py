from __future__ import annotations

import math
from collections import Counter
from typing import Any

from app.config import settings


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    distribution = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in distribution.values())


class CaptureAdapter:
    def extract_request_features(self, method: str, path: str, headers: dict[str, str], body: bytes) -> dict[str, Any]:
        entropy = shannon_entropy(body)
        return {
            "phase": "http_features" if not settings.enable_phase2_pcap else "pcap_adapter",
            "method": method,
            "path": path,
            "header_count": len(headers),
            "body_size": len(body),
            "entropy": entropy,
            "has_binary_body": any(b > 127 for b in body[:512]),
        }

    def extract_response_features(self, status_code: int, headers: dict[str, str], body: bytes) -> dict[str, Any]:
        entropy = shannon_entropy(body)
        return {
            "status_code": status_code,
            "header_count": len(headers),
            "body_size": len(body),
            "entropy": entropy,
        }
