# Quick Start: Attack Neural-Gate in 3 Steps

## ⚡ Fastest Path (3 Terminals)

### Terminal 1: Start Vulnerable Server
```bash
cd /home/deepak/Desktop/Neural_Gate
source .venv/bin/activate
python test_server.py
```
**Wait for:** `Running on http://127.0.0.1:3000`

---

### Terminal 2: Start Neural-Gate Proxy
```bash
cd /home/deepak/Desktop/Neural_Gate
source .venv/bin/activate
export NG_TARGET_SERVER=http://localhost:3000
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
**Wait for:** `Uvicorn running on http://127.0.0.1:8000`

---

### Terminal 3: Launch Attacks
```bash
cd /home/deepak/Desktop/Neural_Gate
source .venv/bin/activate
./run_attack_test.sh
```

---

## 📊 Monitor Results

### SOC Dashboard (Real-time)
```bash
# Open in browser
xdg-open neural-gate-siem.html
# or manually: firefox neural-gate-siem.html
```

### API Endpoints
```bash
# Stats
curl http://127.0.0.1:8000/api/stats

# Blocked IPs
curl http://127.0.0.1:8000/api/blocklist

# Agent Scores
curl http://127.0.0.1:8000/api/agents

# Recent Logs
curl http://127.0.0.1:8000/api/logs
```

---

## 🎯 Manual Attack Examples

### SQLi: Login Bypass
```bash
curl -X POST http://127.0.0.1:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'"'"' OR 1=1 --","password":"x"}'
```
**Expected:** `403 Forbidden` + `threat_blocked` event

---

### SQLi: Search Injection
```bash
curl "http://127.0.0.1:8000/api/search?q=test' OR 1=1 --"
```
**Expected:** `403 Forbidden` + IDS alert

---

### XSS: Script Injection
```bash
curl -X POST http://127.0.0.1:8000/api/comment \
  -H "Content-Type: application/json" \
  -d '{"text":"<script>alert(1)</script>"}'
```
**Expected:** `403 Forbidden` + XSS detection

---

### Data Exfiltration
```bash
curl http://127.0.0.1:8000/api/export
```
**Expected:** May return `451` on egress inspection

---

### DDoS Flood
```bash
for i in {1..150}; do curl http://127.0.0.1:8000/health & done
wait
```
**Expected:** `403 Forbidden` after exceeding rate limit

---

## 🔧 Troubleshooting

### Connection Refused?
Check both servers are running:
```bash
curl http://127.0.0.1:3000/health  # Test server
curl http://127.0.0.1:8000/health  # Proxy
```

### IP Blocked?
Unblock yourself:
```bash
curl -X DELETE http://127.0.0.1:8000/api/blocklist/127.0.0.1
```

### Kill Switch Active?
Disable it:
```bash
curl -X DELETE http://127.0.0.1:8000/api/killswitch
```

---

## 📈 Expected Results

| Attack | Response | SIEM Event | Severity |
|--------|----------|------------|----------|
| SQLi Login | 403 | `threat_blocked` | Critical |
| SQLi Search | 403 | `ids_alert` | Critical |
| XSS | 403 | `threat_blocked` | High |
| Exfil | 451 | `reply_denied` | High |
| DDoS | 403 | `threat_blocked` | Critical |

---

## 🧪 Full Test Suite
```bash
./run_attack_test.sh
```

This runs all attacks automatically and shows results.

---

## 📖 Detailed Guide
See [ATTACK_GUIDE.md](ATTACK_GUIDE.md) for comprehensive documentation.
