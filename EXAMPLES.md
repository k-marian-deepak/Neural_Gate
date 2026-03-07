# Neural-Gate Usage Examples

## Example 1: Proxy a test backend

Start a simple backend server (e.g., Flask app on port 3000):

```bash
# Terminal 1: backend
python -c "from flask import Flask; app=Flask('test'); app.route('/')(lambda:'OK'); app.run(port=3000)"
```

Configure Neural-Gate to proxy it:

```bash
# Terminal 2: edit .env or export
export NG_TARGET_SERVER=http://localhost:3000
export NG_PROXY_PORT=8000

source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Test the proxy flow:

```bash
# Terminal 3: client
curl http://localhost:8000/
# You should get "OK" and see logs in Terminal 2
```

---

## Example 2: Run attack simulations locally

Make sure proxy is running on port 8000, then:

```bash
source .venv/bin/activate
python scripts/attack_sqli.py
# Check the proxy logs or SOC dashboard for "threat_blocked" event
```

---

## Example 3: Test against an authorized staging server

```bash
export NG_ALLOW_ATTACK_DEMOS=1
export NG_ATTACK_ALLOWLIST=staging.yourcompany.internal
export NG_PROXY_URL=http://staging.yourcompany.internal:8000

python scripts/attack_all.py
```

**WARNING**: Only run against explicitly authorized test environments you own.

---

## Example 4: Monitor live events via SOC Dashboard

1. Start proxy: `uvicorn app.main:app --host 0.0.0.0 --port 8000`
2. Open `neural-gate-siem.html` in your browser
3. Run demo attacks: `python scripts/attack_all.py`
4. Watch events stream in real-time with severity color-coding

---

## Example 5: Inspect agent scores

```bash
curl http://localhost:8000/api/agents
# Returns last analyzed request's CNN/GRU/entropy scores
```

---

## Example 6: Blocklist management

Block an IP manually:

```bash
curl -X POST http://localhost:8000/api/blocklist/192.168.1.100
```

List blocked IPs:

```bash
curl http://localhost:8000/api/blocklist
```

Unblock an IP:

```bash
curl -X DELETE http://localhost:8000/api/blocklist/192.168.1.100
```

---

## Example 7: Enable kill switch (block all traffic)

```bash
curl -X POST http://localhost:8000/api/killswitch
# All requests now return 503
```

Disable kill switch:

```bash
curl -X DELETE http://localhost:8000/api/killswitch
```
