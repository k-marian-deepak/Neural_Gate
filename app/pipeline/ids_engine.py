from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from typing import Any

from app.pipeline.ids_rules import RULES


class IDSEngine:
    def __init__(self, ddos_window_seconds: int, ddos_max_requests: int) -> None:
        self._compiled = {
            attack_type: [re.compile(pattern) for pattern in patterns]
            for attack_type, patterns in RULES.items()
        }
        self._ddos_window = ddos_window_seconds
        self._ddos_max = ddos_max_requests
        self._req_windows: dict[str, deque[float]] = defaultdict(deque)

    def inspect(self, source_ip: str, method: str, path: str, headers: dict[str, str], body_text: str) -> list[dict[str, Any]]:
        payload = f"{method} {path}\n{headers}\n{body_text}"
        alerts: list[dict[str, Any]] = []

        for attack_type, patterns in self._compiled.items():
            if any(pattern.search(payload) for pattern in patterns):
                alerts.append(
                    {
                        "event": "ids_alert",
                        "source_ip": source_ip,
                        "attack_type": attack_type,
                        "severity": self._severity_for(attack_type),
                        "message": f"IDS signature matched: {attack_type}",
                    }
                )

        if self._is_ddos(source_ip):
            alerts.append(
                {
                    "event": "ids_alert",
                    "source_ip": source_ip,
                    "attack_type": "ddos",
                    "severity": "critical",
                    "message": "Rate threshold exceeded",
                }
            )

        return alerts

    def _is_ddos(self, source_ip: str) -> bool:
        now = time.time()
        window = self._req_windows[source_ip]
        window.append(now)
        while window and (now - window[0]) > self._ddos_window:
            window.popleft()
        return len(window) > self._ddos_max

    @staticmethod
    def _severity_for(attack_type: str) -> str:
        if attack_type in {"sqli", "command_injection", "reverse_shell", "ddos"}:
            return "critical"
        if attack_type in {"xss", "lfi", "rfi", "xxe", "ssrf"}:
            return "high"
        return "medium"
