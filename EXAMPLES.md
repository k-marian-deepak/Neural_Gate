# Neural-Gate Usage Examples (Current)

## Example 1: Start transparent mode

```bash
cd /home/deepak/Desktop/Neural_Gate
./start_transparent.sh
```

Traffic path:

- attacker -> `127.0.0.1:3000`
- redirected to Neural-Gate `127.0.0.1:8000`
- forwarded to backend `127.0.0.1:3001`

## Example 2: Run attack suite against public target

```bash
NG_ATTACK_BASE_URL=http://127.0.0.1:3000 ./run_attack_test.sh
```

## Example 3: Inspect live telemetry

```bash
curl http://127.0.0.1:8000/api/stats
curl "http://127.0.0.1:8000/api/siem/events?limit=20"
curl http://127.0.0.1:8000/api/agents
```

## Example 4: Analyst feedback (manual legit/not legit)

```bash
curl -X POST http://127.0.0.1:8000/api/adaptive/feedback \
	-H "Content-Type: application/json" \
	-d '{"fingerprint":"<PASTE_FINGERPRINT>","label":"legit","source_ip":"127.0.0.1"}'

curl -X POST http://127.0.0.1:8000/api/adaptive/feedback \
	-H "Content-Type: application/json" \
	-d '{"fingerprint":"<PASTE_FINGERPRINT>","label":"malicious","source_ip":"127.0.0.1"}'

curl http://127.0.0.1:8000/api/adaptive/stats
```

## Example 5: Blocklist and kill switch

```bash
curl http://127.0.0.1:8000/api/blocklist
curl -X DELETE http://127.0.0.1:8000/api/blocklist/127.0.0.1

curl -X POST http://127.0.0.1:8000/api/killswitch
curl -X DELETE http://127.0.0.1:8000/api/killswitch
```

## Example 6: Transparent mode cleanup

```bash
sudo bash scripts/transparent_off.sh 3000 8000
bash scripts/fix_error_98.sh 8000 3000 3001
```
