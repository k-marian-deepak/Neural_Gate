# Neural-Gate Phase 2 Quick Reference

## Setup Checklist

```bash
# 1. Install dependencies
pip install scapy pyshark

# 2. Grant capabilities (recommended method)
sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python3

# 3. Verify setup
./verify_phase2.py

# 4. Start Phase 2
./start_phase2.sh
```

## Manual Configuration

Create `.env` file:
```bash
NG_ENABLE_PHASE2_PCAP=true
NG_PCAP_INTERFACE=lo              # or eth0, wlan0, etc.
NG_PCAP_FILTER="tcp port 8000"   # BPF filter
NG_PCAP_SAVE_ENABLED=true        # Save to disk
NG_PCAP_SAVE_PATH=pcap_dumps
```

## Common BPF Filters

| Use Case | BPF Filter |
|----------|------------|
| Proxy traffic only | `tcp port 8000` |
| Specific IP | `host 192.168.1.100` |
| HTTP/HTTPS | `tcp port 80 or tcp port 443` |
| Exclude SSH | `tcp and not port 22` |
| Specific subnet | `net 192.168.1.0/24` |

## Troubleshooting

### Permission Denied
```bash
# Check capabilities
getcap .venv/bin/python3

# Re-grant if needed
sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python3

# Or run with sudo
sudo -E uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### No Packets Captured
```bash
# Check interface exists
ip link show

# Test with tcpdump
sudo tcpdump -i lo -c 5

# Verify BPF filter syntax
tcpdump -i lo "tcp port 8000" -c 1
```

### High CPU Usage
- Use more restrictive BPF filters
- Disable PCAP saving: `NG_PCAP_SAVE_ENABLED=false`
- Capture on specific interface only

## File Locations

```
Neural_Gate/
├── .env.phase2          # Phase 2 config template
├── start_phase2.sh      # Interactive setup script
├── verify_phase2.py     # Verification tool
├── PHASE2_PCAP.md       # Full documentation
└── pcap_dumps/          # Saved PCAP files
    └── capture_*.pcap
```

## Testing Phase 2

```bash
# Terminal 1: Start Neural-Gate with Phase 2
./start_phase2.sh

# Terminal 2: Start test server
python test_server.py

# Terminal 3: Run attacks
./run_attack_test.sh

# Terminal 4: Monitor PCAP files
watch -n 1 'ls -lh pcap_dumps/'

# Terminal 5: Analyze with tcpdump
tcpdump -r pcap_dumps/capture_*.pcap -n
```

## Performance Tips

1. **Interface Selection**: Use `lo` for local testing, specific NIC for production
2. **BPF Filters**: More specific = better performance
3. **PCAP Saving**: Disable if not needed for forensics
4. **Rotation**: PCAP files rotate every 3600 seconds (configurable)

## Comparison: Phase 1 vs Phase 2

| Feature | Phase 1 (HTTP) | Phase 2 (PCAP) |
|---------|----------------|----------------|
| Setup | Easy | Requires sudo/capabilities |
| Performance | Fast | Moderate (packet overhead) |
| Visibility | HTTP only | Full network stack |
| Forensics | Limited | Full PCAP dumps |
| Use Case | Production | Security analysis |

---

**Next Steps:**
1. Run `./verify_phase2.py` to check your setup
2. Execute `./start_phase2.sh` for guided startup
3. Review [PHASE2_PCAP.md](PHASE2_PCAP.md) for detailed docs
