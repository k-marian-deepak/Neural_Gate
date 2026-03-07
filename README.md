# NEURAL-GATE 2026 — Backend

Autonomous AI Proxy Firewall with CNN-based threat detection.
Acts as a **transparent reverse proxy** between clients and your backend server.
Every request AND every reply is inspected in real-time.

---

## Architecture

```
Attacker / Client
      │
      ▼
┌─────────────────────────────────────┐
│         NEURAL-GATE PROXY           │  ← FastAPI on port 8000
│                                     │
│  1. PCAP Capture (raw packet bytes) │
│  2. IDS Engine  (Snort-style rules) │
│  3. SIEM Correlator (event store)   │
│  4. AI Multi-Agent CNN Analysis     │
│     ├── CNN Header Inspector        │
│     ├── CNN Body Inspector          │
│     ├── GRU Temporal Tracker        │
│     └── Entropy Analyzer            │
│  5. SOAR Automation (playbooks)     │
│  6. Firewall (block / allow / deny) │
│  7. Egress Reply Inspector          │
└─────────────────────────────────────┘
      │                     │
      ▼                     ▼
 Backend Server       SOC Dashboard
 (your app)           WebSocket ws://localhost:8000/ws/soc
```

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Train the CNN model (first time only, ~30 seconds)
```bash
python scripts/train_model.py
```
This generates `app/models/neural_gate_cnn.pt`

### 3. Configure your target server
Edit `config.py`:
```python
TARGET_SERVER = "http://localhost:3000"   # your actual backend
PROXY_PORT    = 8000
```

### 4. Run the proxy
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 5. Point your clients at port 8000
Instead of hitting `http://your-server:3000` directly,
clients hit `http://your-server:8000` — Neural-Gate proxies everything.

### 6. Open the SOC Dashboard
Open `neural-gate-siem.html` in your browser.
It connects to `ws://localhost:8000/ws/soc` automatically.

---

## Live Attack Demo

The `scripts/` folder contains attack scripts you can run against the proxy:

```bash
# SQL Injection
python scripts/attack_sqli.py

# XSS
python scripts/attack_xss.py

# DDoS flood
python scripts/attack_ddos.py

# Data exfiltration simulation (triggers egress check)
python scripts/attack_exfil.py

# Run all attacks in sequence
python scripts/attack_all.py
```

---

## REST API

| Method | Endpoint              | Description                        |
|--------|-----------------------|------------------------------------|
| GET    | /api/logs             | All incident logs (paginated)      |
| GET    | /api/logs?type=sqli   | Filter by attack type              |
| GET    | /api/logs?sev=critical| Filter by severity                 |
| GET    | /api/stats            | Live counters (blocked, denied...) |
| GET    | /api/blocklist        | Currently blocked IPs              |
| DELETE | /api/blocklist/{ip}   | Unblock an IP                      |
| POST   | /api/killswitch       | Kill all traffic                   |
| DELETE | /api/killswitch       | Re-enable traffic                  |
| GET    | /api/agents           | Current CNN agent scores           |
| GET    | /health               | Health check                       |

---

## WebSocket Events (SOC Dashboard)

Connect to `ws://localhost:8000/ws/soc`

Every event is JSON:
```json
{
  "event":     "threat_blocked",
  "timestamp": "2026-03-07T20:45:12Z",
  "source_ip": "185.220.101.47",
  "attack_type": "sqli",
  "severity":  "critical",
  "phase":     "CNN → SOAR",
  "agents": {
    "header_score": 0.91,
    "body_score":   0.97,
    "gru_score":    0.88,
    "entropy":      7.2
  },
  "confidence": 0.97,
  "action":    "BLOCKED",
  "message":   "SQL injection detected in POST body targeting /api/login"
}
```

Event types: `threat_blocked`, `reply_denied`, `request_allowed`,
             `ids_alert`, `soar_action`, `kill_switch`, `agent_update`

---

## CNN Model Architecture

```
Input: 1024-byte packet payload as float32 vector
  │
  ├── Conv1D(32 filters, kernel=8, ReLU)
  ├── MaxPool1D(4)
  ├── Conv1D(64 filters, kernel=4, ReLU)
  ├── MaxPool1D(4)
  ├── Conv1D(128 filters, kernel=3, ReLU)
  ├── AdaptiveAvgPool
  ├── GRU(hidden=64, layers=2, bidirectional)
  ├── Dropout(0.4)
  └── Linear → Sigmoid → P(malicious) [0..1]
```

Threshold: `P > 0.85` → BLOCK

---

## IDS Signature Rules

Located in `app/pipeline/ids_rules.py`
Rules cover: SQLi, XSS, LFI, RFI, Command Injection, XXE, SSRF,
             Port Scans, DDoS patterns, Shellcode, Reverse shells

---

## File Structure

```
neural-gate/
├── app/
│   ├── main.py              # FastAPI app, proxy logic, WebSocket
│   ├── config.py            # All configuration
│   ├── agents/
│   │   ├── cnn_model.py     # PyTorch CNN+GRU model definition
│   │   ├── header_agent.py  # CNN Header Inspector
│   │   ├── body_agent.py    # CNN Body Inspector
│   │   ├── gru_agent.py     # GRU Temporal Tracker
│   │   ├── entropy_agent.py # Entropy Analyzer
│   │   └── egress_agent.py  # Reply Inspector (exfiltration)
│   ├── pipeline/
│   │   ├── pcap_capture.py  # Packet capture & feature extraction
│   │   ├── ids_engine.py    # Snort-style signature matching
│   │   ├── siem.py          # Event correlation & log store
│   │   └── soar.py          # Automated response playbooks
│   └── api/
│       ├── routes.py        # REST API routes
│       └── websocket.py     # SOC WebSocket manager
├── scripts/
│   ├── train_model.py       # Train CNN on synthetic data
│   ├── attack_sqli.py       # SQLi attack demo
│   ├── attack_xss.py        # XSS attack demo
│   ├── attack_ddos.py       # DDoS attack demo
│   ├── attack_exfil.py      # Exfiltration attack demo
│   └── attack_all.py        # Run all attacks
├── config.py                # Root config
├── requirements.txt
└── README.md
```
