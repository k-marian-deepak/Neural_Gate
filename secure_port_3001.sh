#!/bin/bash

echo "========================================"
echo "Securing Port 3001 with iptables"
echo "========================================"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root (use: sudo bash secure_port_3001.sh)"
   exit 1
fi

echo "[*] Blocking direct access to port 3001..."

# Flush existing rules for port 3001 (if any)
iptables -D INPUT -p tcp --dport 3001 -j DROP 2>/dev/null || true

# Block direct access to port 3001 from external sources
# Only localhost (127.0.0.1) can access it
iptables -A INPUT -p tcp --dport 3001 ! -s 127.0.0.1 -j DROP

echo "[✓] Port 3001 is now blocked for external access"
echo "[✓] Only localhost (127.0.0.1) can access port 3001"
echo ""

echo "========================================"
echo "Verification"
echo "========================================"
echo ""
echo "Try these commands:"
echo ""
echo "1. Direct access (should FAIL after ~5 seconds):"
echo "   timeout 5 curl http://127.0.0.1:3001/health || echo 'BLOCKED (Expected)'"
echo ""
echo "2. Via Neural-Gate proxy (should SUCCEED):"
echo "   curl http://127.0.0.1:8000/health"
echo ""

# Save rules to persist across reboot
echo ""
echo "[*] Saving iptables rules to persist across reboot..."
iptables-save > /etc/iptables/rules.v4 2>/dev/null || {
    echo "[!] Could not save rules (iptables-persistent not installed)"
    echo "    Run: sudo apt-get install iptables-persistent"
}

echo ""
echo "[✓] Security rules applied!"
