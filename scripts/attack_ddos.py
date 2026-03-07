from __future__ import annotations

import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from scripts._common import require_safe_target, send


def run() -> None:
    base = os.getenv("NG_PROXY_URL", "http://localhost:8000")
    require_safe_target(base)

    total = int(os.getenv("NG_DDOS_REQUESTS", "200"))
    workers = min(int(os.getenv("NG_DDOS_WORKERS", "20")), 30)

    def _request_once(i: int) -> int:
        response = send(base, "GET", f"/health?burst={i}")
        return response.status_code

    statuses: list[int] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_request_once, i) for i in range(total)]
        for fut in as_completed(futures):
            statuses.append(fut.result())

    blocked = sum(1 for status in statuses if status in {403, 429, 503})
    print(f"DDoS demo sent={total}, blocked_or_limited={blocked}, sample={statuses[:10]}")


if __name__ == "__main__":
    run()
