# Neural-Gate Attack Testing Guide

## Step-by-Step Setup & Attack Instructions

### Prerequisites
- Neural-Gate installed and configured (see README.md)
- Virtual environment activated: `source .venv/bin/activate`

---

## STEP 1: Start in Transparent MITM Mode (recommended)

```bash
cd /home/deepak/Desktop/Neural_Gate
source .venv/bin/activate
./start_transparent.sh
```

This starts the current architecture:

- Public port (attacker target): `127.0.0.1:3000`
- Neural-Gate proxy: `127.0.0.1:8000`
- Vulnerable backend: `127.0.0.1:3001`

---

## STEP 2: Open SOC Dashboard (Optional but Recommended)
Open `neural-gate-siem.html` in your browser:
```bash
# In a new terminal
cd /home/deepak/Desktop/Neural_Gate
firefox neural-gate-siem.html
# or
google-chrome neural-gate-siem.html
```

You should see **"CONNECTED"** status and a live event feed.

---

## STEP 3: Run Attacks (hit public port 3000)

### Option A: Automated Test Suite

```bash
# Terminal 3
cd /home/deepak/Desktop/Neural_Gate
source .venv/bin/activate
chmod +x run_attack_test.sh
NG_ATTACK_BASE_URL=http://127.0.0.1:3000 ./run_attack_test.sh
```

### Option B: Manual Attack Commands

#### Attack 1: SQL Injection (Login Bypass)

```bash
# This should be BLOCKED by Neural-Gate
curl -X POST http://127.0.0.1:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'"'"' OR 1=1 --","password":"x"}'
```

**Expected Result:**
- Status: `403 Forbidden`
- Response: `{"detail":"Threat confidence exceeded threshold","action":"BLOCKED"}`
- SOC Dashboard: Event `threat_blocked` with severity `critical`

---

#### Attack 2: SQL Injection (Search)

```bash
curl "http://127.0.0.1:3000/api/search?q=test' OR 1=1 --"
```

**Expected Result:**
- Status: `403 Forbidden`
- IDS alert for SQLi pattern
- IP auto-blocked for 30 minutes

---

#### Attack 3: XSS (Cross-Site Scripting)

```bash
curl -X POST http://127.0.0.1:3000/api/comment \
  -H "Content-Type: application/json" \
  -d '{"post_id":1,"user_id":1,"text":"<script>alert(document.cookie)</script>"}'
```

**Expected Result:**
- Status: `403 Forbidden`
- IDS alert for XSS pattern
- Event logged in SIEM

---

#### Attack 4: Information Exfiltration

```bash
curl http://127.0.0.1:3000/api/export
```

**Expected Result:**
- May return `200` initially
- Egress inspection triggers on high-entropy response
- If entropy threshold exceeded: `451 Unavailable For Legal Reasons`

---

#### Attack 5: DDoS Flooding

```bash
for i in {1..150}; do 
    curl http://127.0.0.1:3000/health &
done
wait
```

**Expected Result:**
- After ~120 requests in 10 seconds: `403 Forbidden`
- IDS alert: `ddos` attack type
- IP auto-blocked

---

## STEP 4: Monitor Results

### Check Neural-Gate Stats

```bash
curl http://127.0.0.1:8000/api/stats
```

**Output:**
```json
{
  "total_events": 25,
  "blocked_or_denied": 8,
  "kill_switch_enabled": false,
  "active_blocked_ips": 1,
  "event_counts": {
    "threat_blocked": 5,
    "ids_alert": 8,
    "agent_update": 12
  }
}
```

---

### View Attack Logs

```bash
# All logs
curl http://127.0.0.1:8000/api/logs

# SQLi attacks only
curl "http://127.0.0.1:8000/api/logs?type=sqli"

# Critical severity only
curl "http://127.0.0.1:8000/api/logs?sev=critical"
```

---

### Check Blocked IPs

```bash
curl http://127.0.0.1:8000/api/blocklist
```

**Output:**
```json
{
  "blocked_ips": ["127.0.0.1"]
}
```

---

### View Agent Scores

```bash
curl http://127.0.0.1:8000/api/agents
```

**Output:**
```json
{
  "header_score": 0.8234,
  "body_score": 0.9156,
  "gru_score": 0.8745,
  "entropy": 5.234,
  "entropy_score": 0.7123,
  "confidence": 0.8567
}
```

---

## STEP 5: Manual Adaptive Feedback (legit/not legit)

```bash
# 1) Get recent events and pick a fingerprint
curl "http://127.0.0.1:8000/api/siem/events?limit=50"

# 2) Mark as legit
curl -X POST http://127.0.0.1:8000/api/adaptive/feedback \
  -H "Content-Type: application/json" \
  -d '{"fingerprint":"<PASTE_FINGERPRINT>","label":"legit","source_ip":"127.0.0.1"}'

# 3) Mark as malicious
curl -X POST http://127.0.0.1:8000/api/adaptive/feedback \
  -H "Content-Type: application/json" \
  -d '{"fingerprint":"<PASTE_FINGERPRINT>","label":"malicious","source_ip":"127.0.0.1"}'

# 4) Verify adaptive stats
curl http://127.0.0.1:8000/api/adaptive/stats
```

---

## STEP 6: Advanced Attack Scenarios

### Scenario 1: Bypass Attempt with Encoding

```bash
# URL-encoded SQLi
curl -X POST http://127.0.0.1:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin%27%20OR%201=1%20--","password":"x"}'
```

### Scenario 2: Union-Based SQLi

```bash
curl -X POST http://127.0.0.1:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"x'"'"' UNION SELECT 1,2,3 --","password":"x"}'
```

### Scenario 3: XSS with Event Handlers

```bash
curl -X POST http://127.0.0.1:3000/api/comment \
  -H "Content-Type: application/json" \
  -d '{"text":"<img src=x onerror=alert(1)>"}'
```

### Scenario 4: Path Traversal

```bash
curl http://127.0.0.1:3000/api/user/1
curl http://127.0.0.1:3000/api/user/2
```

---

## STEP 7: Test Kill Switch

### Enable Kill Switch (Block All Traffic)

```bash
curl -X POST http://127.0.0.1:8000/api/killswitch
```

**Result:** All subsequent requests return `503 Service Unavailable`

### Test Blocked Traffic

```bash
curl http://127.0.0.1:8000/health
# Returns: {"detail":"Kill switch enabled","action":"DENIED"}
```

### Disable Kill Switch

```bash
curl -X DELETE http://127.0.0.1:8000/api/killswitch
```

---

## STEP 8: Unblock IPs (Optional)

```bash
# Unblock your IP to continue testing
curl -X DELETE http://127.0.0.1:8000/api/blocklist/127.0.0.1
```

---

## Attack Cheat Sheet

| Attack Type | Command | Expected Block |
|-------------|---------|----------------|
| SQLi Login | `curl -X POST ... -d '{"username":"admin' OR 1=1 --"}'` | ✅ 403 |
| SQLi Search | `curl ".../search?q=test' OR 1=1 --"` | ✅ 403 |
| XSS | `curl -X POST ... -d '{"text":"<script>alert(1)</script>"}'` | ✅ 403 |
| Exfil | `curl .../export` | ⚠️ 451 (egress) |
| DDoS | `for i in {1..200}; do curl ... & done` | ✅ 403 |

---

## Troubleshooting

### "Connection refused" errors
- Ensure backend is running on `127.0.0.1:3001`
- Ensure Neural-Gate proxy is running on `127.0.0.1:8000`
- Ensure transparent redirect exists for `3000 -> 8000`

### All requests return 502
- Check `NG_TARGET_SERVER` is set correctly
- Verify backend is accessible: `curl http://localhost:3001/health`

### No events in SOC dashboard
- Refresh browser page
- Check WebSocket connection in browser console
- Verify proxy is running: `curl http://127.0.0.1:8000/health`

### IP blocked, can't test anymore
```bash
curl -X DELETE http://127.0.0.1:8000/api/blocklist/127.0.0.1
```

---

## Clean Up

```bash
# Stop servers (Ctrl+C in each terminal)
# Remove test database
rm test_app.db
```

---

## What to Observe

1. **Terminal 2 (Proxy Logs):** See incoming requests and block decisions
2. **SOC Dashboard:** Real-time event stream with color-coded severity
3. **API Stats:** Counters increment as attacks are detected
4. **Blocklist:** IPs automatically added after critical events
5. **Agent Scores:** CNN/GRU confidence values for each request

---

## Next Steps

- Adjust thresholds in `.env` file
- Train model on real attack data
- Add custom IDS rules in `app/pipeline/ids_rules.py`
- Enable Phase-2 PCAP capture for packet-level inspection
