# Testing Neural-Gate (Current State)

## Current Topology

- Public target: `127.0.0.1:3000`
- Neural-Gate proxy: `127.0.0.1:8000`
- Vulnerable backend: `127.0.0.1:3001`

## 1) Start Stack (transparent mode)

```bash
cd /home/deepak/Desktop/Neural_Gate
./start_transparent.sh
```

## 2) Health Validation

```bash
curl http://127.0.0.1:3000/health
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:3001/health
```

## 3) Attack Validation

```bash
NG_ATTACK_BASE_URL=http://127.0.0.1:3000 ./run_attack_test.sh
```

## 4) SOC and SIEM Validation

```bash
curl http://127.0.0.1:8000/api/stats
curl "http://127.0.0.1:8000/api/siem/events?limit=20"
curl http://127.0.0.1:8000/api/logs
```

## 5) Manual Adaptive Feedback (legit/not legit)

```bash
# Inspect events and copy fingerprint from a recent detection
curl "http://127.0.0.1:8000/api/siem/events?limit=50"

# Mark as legit
curl -X POST http://127.0.0.1:8000/api/adaptive/feedback \
  -H "Content-Type: application/json" \
  -d '{"fingerprint":"<PASTE_FINGERPRINT>","label":"legit","source_ip":"127.0.0.1"}'

# Mark as malicious
curl -X POST http://127.0.0.1:8000/api/adaptive/feedback \
  -H "Content-Type: application/json" \
  -d '{"fingerprint":"<PASTE_FINGERPRINT>","label":"malicious","source_ip":"127.0.0.1"}'

# Check learning stats
curl http://127.0.0.1:8000/api/adaptive/stats
```

## 6) Recovery / Control

```bash
# Fix port conflicts (error 98)
bash scripts/fix_error_98.sh 8000 3000 3001

# Remove transparent redirect
sudo bash scripts/transparent_off.sh 3000 8000

# Disable kill switch if enabled
curl -X DELETE http://127.0.0.1:8000/api/killswitch
```
