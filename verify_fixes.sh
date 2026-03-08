#!/bin/bash

echo "========================================"
echo "Neural-Gate - Quick Verification Script"
echo "========================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "[*] Checking if services are running..."
echo ""

# Test Port 3001 (Vulnerable Server)
echo -n "Port 3001 (Vulnerable Test Server): "
if timeout 2 curl -s http://127.0.0.1:3001/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Running${NC}"
    SERVER_OK=1
else
    echo -e "${RED}✗ Not running${NC}"
    SERVER_OK=0
fi

# Test Port 8000 (Neural-Gate Proxy)
echo -n "Port 8000 (Neural-Gate Proxy): "
if timeout 2 curl -s http://127.0.0.1:8000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Running${NC}"
    PROXY_OK=1
else
    echo -e "${RED}✗ Not running${NC}"
    PROXY_OK=0
fi

echo ""

if [[ $SERVER_OK -eq 0 ]] || [[ $PROXY_OK -eq 0 ]]; then
    echo -e "${YELLOW}[!] Services not running. Start them first:${NC}"
    echo ""
    echo "Terminal 1: python test_server.py"
    echo "Terminal 2: uvicorn app.main:app --host 127.0.0.1 --port 8000"
    echo ""
    exit 1
fi

echo "========================================"
echo "Test 1: Neural-Gate API Endpoints"
echo "========================================"
echo ""

echo "Stats:"
curl -s http://127.0.0.1:8000/api/stats | python -m json.tool
echo ""

echo "Blocklist:"
curl -s http://127.0.0.1:8000/api/blocklist | python -m json.tool
echo ""

echo "Latest Events/Logs (limit 3):"
curl -s "http://127.0.0.1:8000/api/logs?limit=3" | python -m json.tool
echo ""

echo "Adaptive Stats:"
curl -s http://127.0.0.1:8000/api/adaptive/stats | python -m json.tool
echo ""

echo "========================================"
echo "Test 2: Run a SQL Injection Attack"
echo "========================================"
echo ""
echo "Sending SQLi attack to port 8000..."
RESPONSE=$(curl -s -X POST http://127.0.0.1:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin\" OR \"1\"=\"1","password":"admin"}')

echo "Response: $RESPONSE"
echo ""

if echo "$RESPONSE" | grep -q "BLOCKED"; then
    echo -e "${GREEN}✓ Attack was BLOCKED by Neural-Gate${NC}"
else
    echo -e "${YELLOW}⚠ Attack may not have been blocked${NC}"
fi
echo ""

echo "========================================"
echo "Test 3: Check Blocklist After Attack"
echo "========================================"
echo ""
sleep 1
curl -s http://127.0.0.1:8000/api/blocklist | python -m json.tool
echo ""

echo "========================================"
echo "Test 4: Check Latest Events"
echo "========================================"
echo ""
curl -s "http://127.0.0.1:8000/api/logs?limit=5" | python -m json.tool
echo ""

echo "========================================"
echo "Verification Complete!"
echo "========================================"
echo ""
echo "If blocklist is still empty after blocked attacks, check:"
echo "  1. Malicious threshold in config (currently 0.85)"
echo "  2. Source IP extraction (should be 127.0.0.1)"
echo "  3. SOAR engine blocking logic"
echo ""
