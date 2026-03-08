#!/bin/bash

set -euo pipefail

PORTS=("$@")
if [[ ${#PORTS[@]} -eq 0 ]]; then
  PORTS=(8000 3000 3001)
fi
has_failures=0

echo "========================================"
echo "Neural-Gate Port Recovery (Error 98 Fix)"
echo "========================================"

kill_port() {
  local port="$1"
  echo ""
  echo "[+] Checking port $port"

  local pids
  pids=$(lsof -t -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)

  if [[ -z "$pids" ]]; then
    echo "    - No LISTEN process found by lsof"
  else
    echo "    - Found PID(s): $pids"
    for pid in $pids; do
      local cmd
      cmd=$(ps -p "$pid" -o args= 2>/dev/null || true)
      echo "    - Killing PID $pid :: ${cmd:-unknown}"
      kill "$pid" 2>/dev/null || true
    done
    sleep 1
    for pid in $pids; do
      if kill -0 "$pid" 2>/dev/null; then
        echo "    - Force killing PID $pid"
        kill -9 "$pid" 2>/dev/null || true
      fi
    done
  fi

  echo "    - Fuser fallback for port $port"
  fuser -k "$port"/tcp >/dev/null 2>&1 || true

  if ss -ltn | grep -q ":$port "; then
    echo "    - WARNING: port $port still appears active"
    if command -v sudo >/dev/null 2>&1; then
      echo "    - Try with elevated privileges: sudo fuser -k $port/tcp"
      echo "    - Or inspect owner: sudo ss -ltnp | grep ':$port'"
    fi
    has_failures=1
  else
    echo "    - Port $port is now free"
  fi
}

for port in ${PORTS[@]}; do
  kill_port "$port"
done

echo ""
echo "[+] Final listener check"
port_pattern=""
for port in "${PORTS[@]}"; do
  if [[ -z "$port_pattern" ]]; then
    port_pattern=":${port}"
  else
    port_pattern="${port_pattern}|:${port}"
  fi
done
ss -ltnp | grep -E "${port_pattern}" || echo "    - No listeners on ${PORTS[*]}"

echo ""
if [[ "$has_failures" -eq 0 ]]; then
  echo "Done. Ports are clear; you can start the proxy without error 98."
else
  echo "Ports are still busy. Run the suggested sudo command(s), then retry." 
  exit 1
fi
