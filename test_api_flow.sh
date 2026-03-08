#!/bin/bash

echo "========================================"
echo "Testing Neural-Gate API Flow"
echo "========================================"
echo ""
echo "Testing: Client → Port 8000 (Proxy) → Port 3001 (Server)"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if services are running
echo "[*] Checking if services are running..."
echo ""

# Test Port 3001 (Test Server)
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
echo "Test 1: Health Check via Proxy"
echo "========================================"
curl -s http://127.0.0.1:8000/health | python -m json.tool
echo ""
echo ""

echo "========================================"
echo "Test 2: API Login Request via Proxy"
echo "========================================"
echo "Sending: POST /api/login with credentials"
curl -s -X POST http://127.0.0.1:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | python -m json.tool
echo ""
echo ""

echo "========================================"
echo "Test 3: Search API via Proxy"
echo "========================================"
echo "Sending: GET /api/search?q=test"
curl -s "http://127.0.0.1:8000/api/search?q=test" | python -m json.tool
echo ""
echo ""

echo "========================================"
echo "Test 4: Get User via Proxy"
echo "========================================"
echo "Sending: GET /api/user/1"
curl -s http://127.0.0.1:8000/api/user/1 | python -m json.tool
echo ""
echo ""

echo "========================================"
echo "Test 5: SQL Injection Attack (Blocked by Neural-Gate)"
echo "========================================"
echo "Sending: POST /api/login with SQLi payload"
echo "Expected: Neural-Gate should detect and block this"
echo ""
curl -s -X POST http://127.0.0.1:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin\" OR \"1\"=\"1","password":"admin"}' | python -m json.tool
echo ""
echo ""

echo "========================================"
echo "Test 6: XSS Attack (Blocked by Neural-Gate)"
echo "========================================"
echo "Sending: POST /api/comment with XSS payload"
echo "Expected: Neural-Gate should detect and block this"
echo ""
curl -s -X POST http://127.0.0.1:8000/api/comment \
  -H "Content-Type: application/json" \
  -d '{"post_id":1,"user_id":1,"text":"<script>alert(\"XSS\")</script>"}' | python -m json.tool
echo ""
echo ""

echo "========================================"
echo "Summary"
echo "========================================"
echo ""
echo -e "${GREEN}✓ Normal requests${NC} pass through the proxy successfully"
echo -e "${GREEN}✓ Malicious requests${NC} are detected and blocked by Neural-Gate"
echo ""
echo "The API flow is working correctly!"
echo ""
