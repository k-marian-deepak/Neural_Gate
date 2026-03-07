# Testing Neural-Gate Locally

## Prerequisites

1. Virtual environment activated: `source .venv/bin/activate`
2. Dependencies installed: `pip install -r requirements.txt`
3. Model trained: `python scripts/train_model.py`

---

## Test 1: Health Check (no backend required)

```bash
# Start proxy
uvicorn app.main:app --host 127.0.0.1 --port 8000

# In another terminal
curl http://127.0.0.1:8000/health
# Expected: {"status":"ok"}
```

---

## Test 2: Inspect API Endpoints (no backend required)

```bash
# Stats
curl http://127.0.0.1:8000/api/stats

# Agent scores
curl http://127.0.0.1:8000/api/agents

# Blocklist
curl http://127.0.0.1:8000/api/blocklist
```

---

## Test 3: Attack Simulations (localhost-safe)

```bash
# Ensure proxy is running on port 8000
python scripts/attack_sqli.py
python scripts/attack_xss.py
python scripts/attack_ddos.py
python scripts/attack_exfil.py

# Or all at once
python scripts/attack_all.py
```

**Note**: These scripts will fail with 502 if no backend is configured on port 3000, but they will still trigger IDS alerts, agent scoring, and SOAR policy evaluation. Check `/api/logs` for events.

---

## Test 4: Proxy Flow with Real Backend

### Option A: Flask backend

```bash
# Terminal 1: start backend
pip install flask
python -c "from flask import Flask, jsonify; app=Flask('test'); app.route('/api/data')(lambda: jsonify({'data':'ok'})); app.run(port=3000)"

# Terminal 2: start proxy
export NG_TARGET_SERVER=http://localhost:3000
uvicorn app.main:app --host 127.0.0.1 --port 8000

# Terminal 3: client
curl http://127.0.0.1:8000/api/data
# Expected (after proxy inspection): {"data":"ok"}
```

### Option B: Node.js/Express backend

```bash
# Terminal 1
npx express-generator backend && cd backend && npm install && npm start
# Backend runs on port 3000

# Terminal 2
export NG_TARGET_SERVER=http://localhost:3000
uvicorn app.main:app --host 127.0.0.1 --port 8000

# Terminal 3
curl http://127.0.0.1:8000/
```

---

## Test 5: WebSocket SOC Dashboard

1. Start proxy: `uvicorn app.main:app --host 127.0.0.1 --port 8000`
2. Open `neural-gate-siem.html` in browser
3. Run attack scripts
4. Observe real-time event stream in dashboard

---

## Test 6: Manual Attack Payloads

```bash
# SQLi payload (will trigger IDS + agent scoring)
curl -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin'\'' OR 1=1 --","pass":"x"}'

# XSS payload
curl -X POST http://127.0.0.1:8000/comment \
  -H "Content-Type: application/json" \
  -d '{"text":"<script>alert(1)</script>"}'
```

Check `/api/logs` or SOC dashboard for detection events.

---

## Test 7: Kill Switch

```bash
# Enable
curl -X POST http://127.0.0.1:8000/api/killswitch

# All traffic now blocked with 503
curl http://127.0.0.1:8000/health
# Expected: {"detail":"Kill switch enabled","action":"DENIED"} (503)

# Disable
curl -X DELETE http://127.0.0.1:8000/api/killswitch
```

---

## Common Issues

### 502 Bad Gateway
- Backend is not running or `NG_TARGET_SERVER` is misconfigured
- Check that backend is accessible: `curl http://localhost:3000`

### Import errors
- Ensure working directory is repo root when running scripts
- Activate venv: `source .venv/bin/activate`

### Model not found
- Run training first: `python scripts/train_model.py`
- Check `app/models/neural_gate_cnn.pt` exists

### WebSocket connection fails
- Ensure proxy is running on port 8000
- Check browser console for errors
- Verify `ws://localhost:8000/ws/soc` is accessible
