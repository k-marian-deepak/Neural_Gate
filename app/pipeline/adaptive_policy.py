from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections import Counter
from dataclasses import dataclass
from threading import Lock
from typing import Any


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


@dataclass
class MemoryEntry:
    q: float = 0.0
    seen: int = 0
    blocked: int = 0
    allowed: int = 0
    ids_hits: int = 0
    last_seen: float = 0.0
    tokens: list[str] | None = None


class AdaptivePolicy:
    TOKEN_RE = re.compile(
        r"(union|select|insert|drop|or\s+1=1|<script|onerror|onload|\.\./|passwd|cmd\.exe|powershell|wget|curl|base64|sleep\()",
        re.IGNORECASE,
    )

    def __init__(
        self,
        enabled: bool,
        learning_rate: float,
        influence: float,
        max_memory: int,
        persist_path: str,
        autosave_every: int,
    ) -> None:
        self.enabled = enabled
        self.learning_rate = float(max(0.01, min(learning_rate, 1.0)))
        self.influence = float(max(0.0, min(influence, 1.0)))
        self.max_memory = int(max(100, max_memory))
        self.persist_path = persist_path
        self.autosave_every = int(max(1, autosave_every))

        self._memory: dict[str, MemoryEntry] = {}
        self._updates = 0
        self._counters: Counter[str] = Counter()
        self._lock = Lock()

        if self.enabled:
            self._load()

    def fingerprint(self, method: str, path: str, body_text: str) -> tuple[str, list[str]]:
        tokens = [m.group(1).lower() for m in self.TOKEN_RE.finditer(f"{path}\n{body_text}")]
        uniq_tokens = sorted(set(tokens))[:8]
        bucket = min(len(body_text) // 64, 32)
        raw = f"{method.upper()}|{path}|{bucket}|{'|'.join(uniq_tokens)}"
        key = hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]
        return key, uniq_tokens

    def adjust_confidence(self, base_confidence: float, fingerprint: str, tokens: list[str]) -> tuple[float, dict[str, Any]]:
        if not self.enabled:
            return base_confidence, {
                "enabled": False,
                "fingerprint": fingerprint,
                "delta": 0.0,
                "q": 0.0,
            }

        now = time.time()
        with self._lock:
            entry = self._memory.get(fingerprint)
            if not entry:
                entry = MemoryEntry(last_seen=now, tokens=tokens)
                self._memory[fingerprint] = entry
            entry.seen += 1
            entry.last_seen = now
            if tokens and not entry.tokens:
                entry.tokens = tokens

            repeat_bonus = min(entry.seen / 200.0, 0.05)
            q_delta = entry.q * self.influence
            delta = q_delta + repeat_bonus
            adjusted = _clamp(base_confidence + delta)
            self._counters["confidence_adjustments"] += 1

        return adjusted, {
            "enabled": True,
            "fingerprint": fingerprint,
            "delta": round(delta, 6),
            "q": round(entry.q, 6),
            "seen": entry.seen,
            "tokens": tokens,
        }

    def learn(self, fingerprint: str, ids_alert_count: int, action: str, confidence: float) -> None:
        if not self.enabled:
            return

        action_upper = action.upper()
        ids_hit = ids_alert_count > 0

        if ids_hit and action_upper == "BLOCKED":
            reward = 1.0
        elif ids_hit and action_upper == "ALLOWED":
            reward = -0.6
        elif not ids_hit and action_upper == "BLOCKED":
            reward = -0.7
        else:
            reward = 0.2

        reward += (confidence - 0.5) * 0.2

        with self._lock:
            entry = self._memory.get(fingerprint)
            if not entry:
                entry = MemoryEntry(last_seen=time.time())
                self._memory[fingerprint] = entry

            entry.q = entry.q + self.learning_rate * (reward - entry.q)
            entry.q = max(-1.0, min(1.0, entry.q))

            if ids_hit:
                entry.ids_hits += 1
            if action_upper == "BLOCKED":
                entry.blocked += 1
            elif action_upper == "ALLOWED":
                entry.allowed += 1

            self._counters["learning_updates"] += 1
            self._updates += 1

            if len(self._memory) > self.max_memory:
                oldest_key = min(self._memory.keys(), key=lambda k: self._memory[k].last_seen)
                self._memory.pop(oldest_key, None)
                self._counters["evictions"] += 1

            if self._updates % self.autosave_every == 0:
                self._save_locked()

    def apply_feedback(self, fingerprint: str, label: str) -> dict[str, Any]:
        if not self.enabled:
            return {"updated": False, "reason": "adaptive learning disabled"}

        normalized = str(label).strip().lower()
        if normalized not in {"malicious", "benign", "false_positive", "false_negative"}:
            return {"updated": False, "reason": "invalid label"}

        with self._lock:
            entry = self._memory.get(fingerprint)
            if not entry:
                entry = MemoryEntry(last_seen=time.time())
                self._memory[fingerprint] = entry

            if normalized in {"malicious", "false_negative"}:
                target = 1.0
            else:
                target = -1.0

            old_q = entry.q
            entry.q = entry.q + self.learning_rate * (target - entry.q)
            entry.q = max(-1.0, min(1.0, entry.q))
            entry.last_seen = time.time()

            self._updates += 1
            self._counters["feedback_updates"] += 1
            self._counters[f"feedback_{normalized}"] += 1

            if self._updates % self.autosave_every == 0:
                self._save_locked()

            return {
                "updated": True,
                "fingerprint": fingerprint,
                "label": normalized,
                "old_q": round(old_q, 6),
                "new_q": round(entry.q, 6),
                "seen": entry.seen,
            }

    def stats(self) -> dict[str, Any]:
        with self._lock:
            entries = len(self._memory)
            avg_q = sum(e.q for e in self._memory.values()) / entries if entries else 0.0
            top = sorted(self._memory.items(), key=lambda kv: abs(kv[1].q), reverse=True)[:10]

        return {
            "enabled": self.enabled,
            "memory_entries": entries,
            "avg_q": round(avg_q, 6),
            "learning_rate": self.learning_rate,
            "influence": self.influence,
            "counters": dict(self._counters),
            "top_patterns": [
                {
                    "fingerprint": key,
                    "q": round(entry.q, 6),
                    "seen": entry.seen,
                    "blocked": entry.blocked,
                    "allowed": entry.allowed,
                    "ids_hits": entry.ids_hits,
                    "tokens": entry.tokens or [],
                }
                for key, entry in top
            ],
        }

    def reset(self) -> None:
        with self._lock:
            self._memory.clear()
            self._counters.clear()
            self._updates = 0
            self._save_locked()

    def shutdown(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._save_locked()

    def _load(self) -> None:
        if not self.persist_path or not os.path.exists(self.persist_path):
            return
        try:
            with open(self.persist_path, "r", encoding="utf-8") as fp:
                raw = json.load(fp)
        except Exception:
            return

        memory_raw = raw.get("memory", {}) if isinstance(raw, dict) else {}
        loaded: dict[str, MemoryEntry] = {}
        for key, value in memory_raw.items():
            try:
                loaded[key] = MemoryEntry(
                    q=float(value.get("q", 0.0)),
                    seen=int(value.get("seen", 0)),
                    blocked=int(value.get("blocked", 0)),
                    allowed=int(value.get("allowed", 0)),
                    ids_hits=int(value.get("ids_hits", 0)),
                    last_seen=float(value.get("last_seen", 0.0)),
                    tokens=list(value.get("tokens") or []),
                )
            except Exception:
                continue
        self._memory = loaded

    def _save_locked(self) -> None:
        if not self.persist_path:
            return

        parent = os.path.dirname(self.persist_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        payload = {
            "memory": {
                key: {
                    "q": entry.q,
                    "seen": entry.seen,
                    "blocked": entry.blocked,
                    "allowed": entry.allowed,
                    "ids_hits": entry.ids_hits,
                    "last_seen": entry.last_seen,
                    "tokens": entry.tokens or [],
                }
                for key, entry in self._memory.items()
            }
        }
        try:
            with open(self.persist_path, "w", encoding="utf-8") as fp:
                json.dump(payload, fp)
        except Exception:
            return