#!/bin/bash

set -euo pipefail

PUBLIC_PORT="${1:-3000}"
PROXY_PORT="${2:-8000}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script requires root privileges."
  echo "Run: sudo bash scripts/transparent_on.sh ${PUBLIC_PORT} ${PROXY_PORT}"
  exit 1
fi

echo "[+] Enabling transparent redirect ${PUBLIC_PORT} -> ${PROXY_PORT}"

iptables -t nat -C OUTPUT -p tcp --dport "${PUBLIC_PORT}" -j REDIRECT --to-ports "${PROXY_PORT}" 2>/dev/null || \
iptables -t nat -A OUTPUT -p tcp --dport "${PUBLIC_PORT}" -j REDIRECT --to-ports "${PROXY_PORT}"

iptables -t nat -C PREROUTING -p tcp --dport "${PUBLIC_PORT}" -j REDIRECT --to-ports "${PROXY_PORT}" 2>/dev/null || \
iptables -t nat -A PREROUTING -p tcp --dport "${PUBLIC_PORT}" -j REDIRECT --to-ports "${PROXY_PORT}"

echo "[+] Active NAT redirect rules for port ${PUBLIC_PORT}:"
iptables -t nat -S OUTPUT | grep -- "--dport ${PUBLIC_PORT}" || true
iptables -t nat -S PREROUTING | grep -- "--dport ${PUBLIC_PORT}" || true

echo "[+] Transparent mode enabled"
