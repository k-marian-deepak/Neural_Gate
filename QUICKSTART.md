# Quick Start (Current Architecture)

This project now defaults to transparent MITM mode:

- Public target (attacker/user hits): `127.0.0.1:3000`
- Neural-Gate proxy: `127.0.0.1:8000`
- Real vulnerable backend: `127.0.0.1:3001`

## Fastest Start

```bash
cd /home/deepak/Desktop/Neural_Gate
chmod +x start_transparent.sh scripts/*.sh run_attack_test.sh
./start_transparent.sh
```

Run attacks against the public app port (not proxy):

```bash
NG_ATTACK_BASE_URL=http://127.0.0.1:3000 ./run_attack_test.sh
```

## Validate Pipeline

```bash
curl http://127.0.0.1:3000/health      # attacker-facing (redirected)
curl http://127.0.0.1:8000/health      # proxy
curl http://127.0.0.1:3001/health      # backend direct
```

## Manual Adaptive Feedback (RL-style)

You can manually mark a fingerprint as `legit` or `malicious`:

```bash
# 1) Pull recent events and copy a fingerprint value
curl "http://127.0.0.1:8000/api/siem/events?limit=20"

# 2) Send analyst feedback
curl -X POST http://127.0.0.1:8000/api/adaptive/feedback \
  -H "Content-Type: application/json" \
  -d '{"fingerprint":"<PASTE_FINGERPRINT>","label":"legit","source_ip":"127.0.0.1"}'

# 3) Check adaptive learning stats
curl http://127.0.0.1:8000/api/adaptive/stats
```

Dashboard also supports this workflow via event actions.

## Error 98 Recovery

```bash
bash scripts/fix_error_98.sh 8000 3000 3001
sudo fuser -k 8000/tcp 3000/tcp 3001/tcp
```

## Disable Transparent Redirect

```bash
sudo bash scripts/transparent_off.sh 3000 8000
```
