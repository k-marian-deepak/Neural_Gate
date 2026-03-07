#!/bin/bash

echo "=================================================="
echo "Neural-Gate End-to-End Attack Test Suite"
echo "=================================================="

PROXY="http://127.0.0.1:8000"

print_test() {
    echo ""
    echo ">>> TEST: $1"
    echo "---"
}

# Test 1: Health
print_test "Proxy Health Check"
curl -s "$PROXY/health"
echo ""

# Test 2: SQLi - OR bypass
print_test "SQLi - OR Clause Bypass"
curl -s -X POST "$PROXY/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'"'"' OR 1=1 --","password":"x"}'
echo ""

# Test 3: SQLi - Search
print_test "SQLi - Search Injection"
curl -s "$PROXY/api/search?q=test' UNION SELECT 1,2,3 --"
echo ""

# Test 4: XSS
print_test "XSS - Script Tag"
curl -s -X POST "$PROXY/api/comment" \
  -H "Content-Type: application/json" \
  -d '{"post_id":1,"user_id":1,"text":"<script>alert(1)</script>"}'
echo ""

# Test 5: Info Disclosure
print_test "Info Disclosure - Export All Users"
curl -s "$PROXY/api/export"
echo ""

# Test 6: DDoS
print_test "DDoS Simulation (50 concurrent requests)"
for i in {1..50}; do 
    curl -s "$PROXY/health" > /dev/null &
done
wait
echo "DDoS test complete"

# Test 7: Stats
print_test "Neural-Gate Stats After Attacks"
curl -s "$PROXY/api/stats"
echo ""

# Test 8: Blocklist
print_test "Blocked IPs"
curl -s "$PROXY/api/blocklist"
echo ""

# Test 9: Agent Scores
print_test "Agent Scores (Last Request)"
curl -s "$PROXY/api/agents"
echo ""

echo ""
echo "=================================================="
echo "Test Complete - Check SOC Dashboard for events"
echo "=================================================="
