#!/bin/bash

echo "========================================"
echo "Neural-Gate Quick Start Script"
echo "========================================"
echo ""

# Check if venv is activated
if [[ -z "$VIRTUAL_ENV" ]]; then
    echo "[!] Virtual environment not activated!"
    echo "[*] Activating .venv..."
    source .venv/bin/activate
fi

# Install Flask if needed
echo "[*] Ensuring Flask is installed..."
pip install flask -q

echo "[*] Recovering ports 8000/3000 (Error 98 prevention)..."
bash scripts/fix_error_98.sh 8000 3000 >/dev/null 2>&1 || true

echo ""
echo "========================================"
echo "Starting Neural-Gate Test Environment"
echo "========================================"
echo ""
echo "This will start 3 terminals:"
echo "  1. Vulnerable Test Server (port 3000)"
echo "  2. Neural-Gate Proxy (port 8000)"
echo "  3. Attack Test Suite"
echo ""
echo "Press Ctrl+C in any terminal to stop"
echo ""

read -p "Press Enter to continue or Ctrl+C to abort..."

# Check if terminals are available
if command -v gnome-terminal &> /dev/null; then
    TERM_CMD="gnome-terminal"
elif command -v xterm &> /dev/null; then
    TERM_CMD="xterm -e"
elif command -v konsole &> /dev/null; then
    TERM_CMD="konsole -e"
else
    echo "[!] No terminal emulator found. Running in manual mode."
    echo ""
    echo "Please run these commands in separate terminals:"
    echo ""
    echo "Terminal 1:"
    echo "  cd /home/deepak/Desktop/Neural_Gate"
    echo "  source .venv/bin/activate"
    echo "  python test_server.py"
    echo ""
    echo "Terminal 2:"
    echo "  cd /home/deepak/Desktop/Neural_Gate"
    echo "  source .venv/bin/activate"
    echo "  export NG_TARGET_SERVER=http://localhost:3001"
    echo "  uvicorn app.main:app --host 127.0.0.1 --port 8000"
    echo ""
    echo "Terminal 3:"
    echo "  cd /home/deepak/Desktop/Neural_Gate"
    echo "  source .venv/bin/activate"
    echo "  ./run_attack_test.sh"
    echo ""
    echo "SOC Dashboard: Open neural-gate-siem.html in your browser"
    echo ""
    exit 0
fi

echo "[*] Starting vulnerable test server..."
$TERM_CMD bash -c "cd /home/deepak/Desktop/Neural_Gate && source .venv/bin/activate && python test_server.py; bash" &

sleep 2

echo "[*] Starting Neural-Gate proxy..."
$TERM_CMD bash -c "cd /home/deepak/Desktop/Neural_Gate && source .venv/bin/activate && export NG_TARGET_SERVER=http://localhost:3001 && uvicorn app.main:app --host 127.0.0.1 --port 8000; bash" &

sleep 3

echo "[*] Opening SOC Dashboard..."
if command -v xdg-open &> /dev/null; then
    xdg-open neural-gate-siem.html &
elif command -v firefox &> /dev/null; then
    firefox neural-gate-siem.html &
fi

sleep 2

echo ""
echo "========================================"
echo "Environment Ready!"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Check that test server is running on http://127.0.0.1:3001"
echo "  2. Check that proxy is running on http://127.0.0.1:8000"
echo "  3. Verify SOC dashboard shows 'CONNECTED'"
echo "  4. Run attack tests: ./run_attack_test.sh"
echo ""
echo "Or run attacks manually:"
echo "  ./run_attack_test.sh"
echo ""
