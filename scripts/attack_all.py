from __future__ import annotations

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from scripts.attack_ddos import run as run_ddos
from scripts.attack_exfil import run as run_exfil
from scripts.attack_sqli import run as run_sqli
from scripts.attack_xss import run as run_xss


def run_all() -> None:
    print("Running SQLi demo...")
    run_sqli()
    print("Running XSS demo...")
    run_xss()
    print("Running DDoS demo...")
    run_ddos()
    print("Running Exfil demo...")
    run_exfil()


if __name__ == "__main__":
    run_all()
