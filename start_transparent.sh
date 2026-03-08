#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="${ROOT_DIR}/.venv/bin/python"
UVICORN="${ROOT_DIR}/.venv/bin/uvicorn"

PUBLIC_PORT="${NG_PUBLIC_PORT:-3000}"
PROXY_PORT="${NG_PROXY_PORT:-8000}"
BACKEND_PORT="${NG_BACKEND_PORT:-3001}"

echo "========================================"
echo "Neural-Gate Transparent MITM Start"
echo "========================================"
echo "Public target port : ${PUBLIC_PORT}"
echo "Proxy port         : ${PROXY_PORT}"
echo "Backend port       : ${BACKEND_PORT}"

cd "${ROOT_DIR}"

echo "[*] Clearing old listeners"
bash scripts/fix_error_98.sh "${PUBLIC_PORT}" "${PROXY_PORT}" "${BACKEND_PORT}" || true

echo "[*] Starting vulnerable backend on ${BACKEND_PORT}"
NG_VULN_SERVER_HOST=127.0.0.1 NG_VULN_SERVER_PORT="${BACKEND_PORT}" "${VENV_PY}" test_server.py > /tmp/neural_gate_backend.log 2>&1 &
BACKEND_PID=$!
echo "    - PID ${BACKEND_PID}"

echo "[*] Starting Neural-Gate proxy on ${PROXY_PORT} (target backend ${BACKEND_PORT})"
NG_TARGET_SERVER="http://127.0.0.1:${BACKEND_PORT}" "${UVICORN}" app.main:app --host 127.0.0.1 --port "${PROXY_PORT}" > /tmp/neural_gate_proxy.log 2>&1 &
PROXY_PID=$!
echo "    - PID ${PROXY_PID}"

echo "[*] Enabling transparent redirect ${PUBLIC_PORT} -> ${PROXY_PORT}"
sudo bash scripts/transparent_on.sh "${PUBLIC_PORT}" "${PROXY_PORT}"

echo ""
echo "[+] Ready"
echo "    - Attackers hit: http://127.0.0.1:${PUBLIC_PORT}"
echo "    - Backend actual: http://127.0.0.1:${BACKEND_PORT}"
echo "    - Dashboard WS: ws://127.0.0.1:${PROXY_PORT}/ws/soc"
echo ""
echo "Run attacks with:"
echo "  NG_ATTACK_BASE_URL=http://127.0.0.1:${PUBLIC_PORT} ./run_attack_test.sh"
