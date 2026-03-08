# Phase 2 PCAP Integration Guide

## Overview

Phase 2 enables **real packet capture** at the network layer using Scapy, providing deeper inspection capabilities beyond HTTP-level features.

---

## Installation

### Install PCAP Dependencies

```bash
cd /home/deepak/Desktop/Neural_Gate
source .venv/bin/activate
pip install scapy pyshark
```

### System Requirements (Linux)

For packet capture, you may need additional permissions:

```bash
# Option 1: Run with sudo (not recommended for production)
sudo .venv/bin/python -m uvicorn app.main:app

# Option 2: Grant capabilities to Python (recommended)
sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python3

# Option 3: Add user to pcap group (Debian/Ubuntu)
sudo usermod -a -G pcap $USER
# Then log out and back in
```

---

## Configuration

### Enable Phase 2 in .env

```bash
# Phase 2 PCAP Settings
NG_ENABLE_PHASE2_PCAP=true
NG_PCAP_INTERFACE=lo              # Network interface (lo, eth0, wlan0, etc.)
NG_PCAP_FILTER="tcp port 8000"   # BPF filter for packet capture
NG_PCAP_SAVE_ENABLED=true        # Save PCAP files to disk
NG_PCAP_SAVE_PATH=pcap_dumps     # Directory for PCAP files
```

### Available Interfaces

Find your network interfaces:

```bash
# List all interfaces
ip link show

# Common interfaces:
# - lo: Loopback (localhost traffic)
# - eth0: Ethernet
# - wlan0: WiFi
# - enp0s3: VirtualBox/VMware
```

---

## BPF Filters

Berkeley Packet Filter (BPF) syntax for capturing specific traffic:

```bash
# Capture only TCP traffic on port 8000
NG_PCAP_FILTER="tcp port 8000"

# Capture all HTTP/HTTPS traffic
NG_PCAP_FILTER="tcp port 80 or tcp port 443 or tcp port 8000"

# Capture traffic from specific IP
NG_PCAP_FILTER="host 192.168.1.100"

# Capture specific subnet
NG_PCAP_FILTER="net 192.168.1.0/24"

# Complex filter (port 8000 and not SSH)
NG_PCAP_FILTER="tcp port 8000 and not port 22"
```

---

## Usage

### Start Neural-Gate with Phase 2

```bash
cd /home/deepak/Desktop/Neural_Gate
source .venv/bin/activate

# Set environment variables
export NG_ENABLE_PHASE2_PCAP=true
export NG_PCAP_INTERFACE=lo
export NG_PCAP_SAVE_ENABLED=true

# Start with appropriate permissions
sudo -E .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Note:** `-E` preserves environment variables when using sudo.

---

## What Phase 2 Captures

### Phase 1 (HTTP-level)
- Request method, path, headers
- Request/response body content
- Shannon entropy of payloads
- Header counts and sizes

### Phase 2 (PCAP-level) **adds:**
- Raw packet bytes
- TCP flags (SYN, ACK, FIN, RST, PSH)
- IP TTL values
- Source/destination ports and IPs
- Packet timing and sequence
- Full packet payloads (before HTTP parsing)
- Network-level anomalies

---

## Features Extracted in Phase 2

```json
{
  "phase": "pcap_enhanced",
  "method": "POST",
  "path": "/api/login",
  "body_size": 45,
  "entropy": 5.2,
  "pcap_features": {
    "packet_size": 512,
    "has_tcp": true,
    "has_ip": true,
    "payload_size": 467,
    "tcp_flags": {
      "syn": false,
      "ack": true,
      "fin": false,
      "rst": false,
      "psh": true
    },
    "src_port": 54321,
    "dst_port": 8000,
    "src_ip": "127.0.0.1",
    "dst_ip": "127.0.0.1",
    "ttl": 64
  }
}
```

---

## PCAP File Storage

When `NG_PCAP_SAVE_ENABLED=true`, packets are saved to disk:

```bash
# PCAP files location
pcap_dumps/
├── capture_20260308_001234.pcap
├── capture_20260308_001240.pcap
└── capture_20260308_001245.pcap
```

### Analyze PCAP Files

```bash
# View with tcpdump
tcpdump -r pcap_dumps/capture_20260308_001234.pcap

# View with Wireshark
wireshark pcap_dumps/capture_20260308_001234.pcap

# View with tshark (terminal Wireshark)
tshark -r pcap_dumps/capture_20260308_001234.pcap

# Filter HTTP traffic
tshark -r pcap_dumps/capture_20260308_001234.pcap -Y http
```

---

## Benefits of Phase 2

1. **Network-layer Detection**
   - Detect attacks before they reach application layer
   - Identify port scans, SYN floods, and network anomalies

2. **Complete Traffic Visibility**
   - See packets that don't complete HTTP requests
   - Detect malformed packets and protocol violations

3. **Forensics**
   - Save complete packet captures for post-incident analysis
   - Replay attacks for testing and training

4. **Advanced Threat Detection**
   - TCP flag analysis (detect SYN floods, stealth scans)
   - TTL anomalies (detect spoofed packets)
   - Timing analysis (detect slow attacks)

---

## Performance Considerations

### Memory Usage
- Phase 2 stores last 1000 packets in memory
- ~1-2 MB of RAM for typical traffic
- PCAP files grow at ~1-10 MB/hour depending on traffic

### CPU Usage
- Packet capture adds ~5-15% CPU overhead
- Minimal impact with BPF filters (kernel-level filtering)
- Background thread handles capture asynchronously

### Disk Usage
- Enable `NG_PCAP_SAVE_ENABLED` only when needed
- Rotate PCAP files regularly
- Compress old captures: `gzip pcap_dumps/*.pcap`

---

## Troubleshooting

### "Permission denied" errors

```bash
# Solution 1: Grant capabilities
sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python3

# Solution 2: Run with sudo
sudo -E .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Verify permissions
getcap .venv/bin/python3
```

### "Scapy not available" warning

```bash
# Install Scapy
pip install scapy pyshark

# Verify installation
python -c "from scapy.all import sniff; print('Scapy OK')"
```

### No packets captured

```bash
# Check interface is active
ip link show lo  # Or your interface

# Verify BPF filter
tcpdump -i lo "tcp port 8000" -c 5

# Check firewall rules
sudo iptables -L -n
```

### High CPU usage

```bash
# Use more restrictive BPF filter
NG_PCAP_FILTER="tcp port 8000 and host 127.0.0.1"

# Reduce packet count per iteration (edit pcap_capture.py)
# Change count=10 to count=5 in _capture_loop
```

---

## Migration Path

### From Phase 1 to Phase 2

1. **Install dependencies:**
   ```bash
   pip install scapy pyshark
   ```

2. **Test without saving:**
   ```bash
   export NG_ENABLE_PHASE2_PCAP=true
   export NG_PCAP_SAVE_ENABLED=false
   ```

3. **Enable saving after testing:**
   ```bash
   export NG_PCAP_SAVE_ENABLED=true
   ```

4. **Monitor disk usage:**
   ```bash
   du -sh pcap_dumps/
   ```

### Hybrid Mode

Run both phases simultaneously:
- Phase 1: HTTP-level features (always active)
- Phase 2: PCAP enhancements (when enabled)

The system automatically falls back to Phase 1 if PCAP capture fails.

---

## Security Considerations

- **Sensitive Data:** PCAP files contain raw traffic including credentials
- **Encryption:** Consider encrypting `pcap_dumps/` directory
- **Retention:** Delete old PCAP files regularly
- **Access Control:** Restrict file permissions
  ```bash
  chmod 700 pcap_dumps/
  ```

---

## Example: Complete Phase 2 Setup

```bash
# 1. Install dependencies
pip install scapy pyshark

# 2. Create .env file
cat > .env << 'EOF'
NG_ENABLE_PHASE2_PCAP=true
NG_PCAP_INTERFACE=lo
NG_PCAP_FILTER=tcp port 8000
NG_PCAP_SAVE_ENABLED=true
NG_PCAP_SAVE_PATH=pcap_dumps
NG_TARGET_SERVER=http://localhost:3001
EOF

# 3. Grant permissions
sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python3

# 4. Start Neural-Gate
uvicorn app.main:app --host 0.0.0.0 --port 8000

# 5. Run attacks and check PCAP files
./run_attack_test.sh
ls -lh pcap_dumps/

# 6. Analyze captures
wireshark pcap_dumps/capture_*.pcap
```

---

## Next Steps

- Integrate PCAP features into CNN model training
- Add packet sequence analysis for temporal patterns
- Implement real-time PCAP streaming to SIEM
- Add protocol-specific parsers (DNS, FTP, SMTP)
