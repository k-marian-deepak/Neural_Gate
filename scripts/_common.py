from __future__ import annotations

import os
import sys
from urllib.parse import urlparse

import requests


def require_safe_target(base_url: str) -> None:
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    allow_env = os.getenv("NG_ALLOW_ATTACK_DEMOS", "0")
    allowlist = set((os.getenv("NG_ATTACK_ALLOWLIST", "localhost,127.0.0.1")).split(","))

    if host in {"localhost", "127.0.0.1"}:
        return

    if allow_env != "1":
        print("Blocked: set NG_ALLOW_ATTACK_DEMOS=1 for authorized staging tests")
        sys.exit(1)

    if host not in allowlist:
        print(f"Blocked: host '{host}' not in NG_ATTACK_ALLOWLIST")
        sys.exit(1)


def send(base_url: str, method: str, path: str, **kwargs):
    url = base_url.rstrip("/") + path
    return requests.request(method=method, url=url, timeout=10, **kwargs)
