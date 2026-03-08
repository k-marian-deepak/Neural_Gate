from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from threading import Lock
from typing import Any


class SIEMStore:
    def __init__(self, max_events: int = 20000, blocklist_persist_path: str | None = None) -> None:
        self._events: deque[dict[str, Any]] = deque(maxlen=max_events)
        self._blocklist: dict[str, datetime] = {}
        self._counters: Counter[str] = Counter()
        self._lock = Lock()
        self.kill_switch_enabled = False
        self._blocklist_persist_path = Path(blocklist_persist_path).expanduser() if blocklist_persist_path else None
        self._load_blocklist()

    def add_event(self, event: dict[str, Any]) -> dict[str, Any]:
        if "timestamp" not in event:
            event["timestamp"] = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._events.appendleft(event)
            self._counters[event.get("event", "unknown")] += 1
            action = str(event.get("action", "")).upper()
            if action in {"BLOCKED", "DENIED"}:
                self._counters["total_blocked_denied"] += 1
        return event

    def get_logs(self, attack_type: str | None, severity: str | None, limit: int, offset: int) -> list[dict[str, Any]]:
        with self._lock:
            logs = list(self._events)
        if attack_type:
            logs = [entry for entry in logs if entry.get("attack_type") == attack_type]
        if severity:
            logs = [entry for entry in logs if entry.get("severity") == severity]
        return logs[offset : offset + limit]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            active_blocked = len([ip for ip in self._blocklist if not self._is_expired(ip)])
            total_events = len(self._events)
            blocked_or_denied = self._counters.get("total_blocked_denied", 0)
        return {
            "total_events": total_events,
            "blocked_or_denied": blocked_or_denied,
            "kill_switch_enabled": self.kill_switch_enabled,
            "active_blocked_ips": active_blocked,
            "event_counts": dict(self._counters),
        }

    def _is_expired(self, ip: str) -> bool:
        expiry = self._blocklist.get(ip)
        if not expiry:
            return True
        if datetime.now(timezone.utc) >= expiry:
            return True
        return False

    def list_blocked_ips(self) -> list[str]:
        self._cleanup_blocklist()
        with self._lock:
            return sorted(list(self._blocklist.keys()))

    def block_ip(self, ip: str, ttl_seconds: int) -> None:
        expiry = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        with self._lock:
            self._blocklist[ip] = expiry
        self._persist_blocklist()

    def unblock_ip(self, ip: str) -> bool:
        with self._lock:
            existed = ip in self._blocklist
            self._blocklist.pop(ip, None)
        self._persist_blocklist()
        return existed

    def is_ip_blocked(self, ip: str) -> bool:
        self._cleanup_blocklist()
        with self._lock:
            return ip in self._blocklist

    def _cleanup_blocklist(self) -> None:
        now = datetime.now(timezone.utc)
        changed = False
        with self._lock:
            expired = [ip for ip, expiry in self._blocklist.items() if now >= expiry]
            for ip in expired:
                self._blocklist.pop(ip, None)
            changed = bool(expired)
        if changed:
            self._persist_blocklist()

    def _load_blocklist(self) -> None:
        if not self._blocklist_persist_path:
            return
        path = self._blocklist_persist_path
        try:
            if not path.exists():
                return
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if not isinstance(data, dict):
                return
            now = datetime.now(timezone.utc)
            loaded: dict[str, datetime] = {}
            for ip, expiry_iso in data.items():
                if not isinstance(ip, str) or not isinstance(expiry_iso, str):
                    continue
                try:
                    expiry = datetime.fromisoformat(expiry_iso)
                except ValueError:
                    continue
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                if now < expiry:
                    loaded[ip] = expiry
            with self._lock:
                self._blocklist = loaded
        except (OSError, json.JSONDecodeError):
            return

    def _persist_blocklist(self) -> None:
        if not self._blocklist_persist_path:
            return
        path = self._blocklist_persist_path
        with self._lock:
            payload = {ip: expiry.isoformat() for ip, expiry in self._blocklist.items()}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = path.with_suffix(path.suffix + ".tmp")
            temp_path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
            temp_path.replace(path)
        except OSError:
            return

    def set_kill_switch(self, enabled: bool) -> None:
        self.kill_switch_enabled = enabled
