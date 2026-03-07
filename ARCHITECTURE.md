# Neural-Gate Architecture Overview

## System Layers

```
┌─────────────────────────────────────────────────────────────┐
│                     CLIENT / ATTACKER                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      NEURAL-GATE PROXY                      │
│                      (FastAPI + uvicorn)                    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  INGRESS INSPECTION PIPELINE                         │  │
│  │                                                       │  │
│  │  1. HTTP Feature Extraction (pcap_capture.py)       │  │
│  │     ├─ Shannon entropy                               │  │
│  │     ├─ Header/body size metrics                      │  │
│  │     └─ Binary payload detection                      │  │
│  │                                                       │  │
│  │  2. IDS Signature Engine (ids_engine.py)            │  │
│  │     ├─ Regex rules: SQLi, XSS, LFI, RFI, XXE...     │  │
│  │     └─ Rate threshold (DDoS detection)              │  │
│  │                                                       │  │
│  │  3. AI Multi-Agent Scoring (agents/)                │  │
│  │     ├─ HeaderAgent   → CNN inference on headers     │  │
│  │     ├─ BodyAgent     → CNN inference on body        │  │
│  │     ├─ GRUAgent      → Temporal rolling score       │  │
│  │     └─ EntropyAgent  → Entropy normalization        │  │
│  │                                                       │  │
│  │  4. SIEM Event Store (siem.py)                      │  │
│  │     ├─ Event log (deque with 20k max)               │  │
│  │     ├─ Blocklist (IP → expiry timestamp)            │  │
│  │     └─ Counters + kill switch state                 │  │
│  │                                                       │  │
│  │  5. SOAR Decision Engine (soar.py)                  │  │
│  │     ├─ Policy: kill switch → DENIED (503)           │  │
│  │     ├─ Policy: IP blocklisted → BLOCKED (403)       │  │
│  │     ├─ Policy: confidence ≥ 0.85 → BLOCKED          │  │
│  │     └─ Default: ALLOWED → forward to backend        │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  EGRESS INSPECTION PIPELINE                          │  │
│  │                                                       │  │
│  │  6. Response Feature Extraction                      │  │
│  │  7. EgressAgent scoring (CNN + entropy)             │  │
│  │  8. SOAR egress policy (score ≥ 0.85 → DENIED 451)  │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  REST API (routes.py)                                │  │
│  │  /api/logs, /api/stats, /api/blocklist,             │  │
│  │  /api/killswitch, /api/agents, /health              │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  WebSocket Broadcast (websocket.py)                  │  │
│  │  ws://localhost:8000/ws/soc                          │  │
│  │  Events: threat_blocked, reply_denied, agent_update  │  │
│  └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                ┌─────────────────────────┐
                │   BACKEND TARGET SERVER │
                │   (configured via       │
                │    NG_TARGET_SERVER)    │
                └─────────────────────────┘
```

---

## Key Components

### 1. **app/main.py**
- FastAPI application entry point
- Catch-all proxy route handler
- Orchestrates ingress/egress pipeline
- Manages runtime state (agents, SIEM, SOAR, WebSocket)

### 2. **app/config.py**
- Pydantic settings with env var support
- All runtime tunables (thresholds, timeouts, blocklist TTL, etc.)

### 3. **app/pipeline/pcap_capture.py**
- Phase-1: HTTP-level feature extraction (current)
- Phase-2: Real packet capture adapter (future)
- Shannon entropy calculation

### 4. **app/pipeline/ids_engine.py**
- Regex-based signature matching (Snort-style)
- DDoS rate limiting per source IP
- Alert severity assignment

### 5. **app/pipeline/siem.py**
- In-memory event store (thread-safe)
- IP blocklist with TTL-based expiration
- Event counters + kill switch state

### 6. **app/pipeline/soar.py**
- Ingress policy: kill switch, blocklist, confidence threshold
- Egress policy: entropy + model score threshold
- Auto-blocklist on critical events

### 7. **app/agents/**
- **cnn_model.py**: PyTorch CNN+GRU definition + inference wrapper
- **header_agent.py**: Score HTTP headers + path
- **body_agent.py**: Score request body
- **gru_agent.py**: Temporal rolling average per IP
- **entropy_agent.py**: Normalize entropy to [0,1]
- **egress_agent.py**: Score response body + entropy

### 8. **app/api/routes.py**
- REST API for logs, stats, blocklist, agents, kill switch

### 9. **app/api/websocket.py**
- WebSocket manager for SOC dashboard
- Broadcasts all events (JSON)

### 10. **scripts/**
- **train_model.py**: Synthetic dataset + 3-epoch CNN training
- **attack_*.py**: Local-only demo scripts (SQLi, XSS, DDoS, exfil)
- **_common.py**: Safety guardrails (allowlist enforcement)

---

## Data Flow: Request Lifecycle

1. **Client → Proxy** (ingress)
2. **Feature Extraction** → entropy, size, binary detection
3. **IDS Signature Matching** → alerts for SQLi, XSS, etc.
4. **Agent Scoring** → CNN inference on headers + body
5. **SOAR Policy Evaluation** → ALLOW / BLOCK / DENY
6. **If ALLOWED** → forward to backend via httpx
7. **Backend → Proxy** (response)
8. **Egress Inspection** → response entropy + model score
9. **Egress SOAR Policy** → ALLOW / DENY
10. **Proxy → Client** (final response or error)

All stages emit events to SIEM and broadcast to WebSocket.

---

## Decision Policies (SOAR)

### Ingress
- **Kill Switch ON** → 503 (DENIED)
- **IP Blocklisted** → 403 (BLOCKED)
- **Confidence ≥ 0.85** → 403 (BLOCKED) + auto-blocklist for 1800s
- **Critical IDS Alert** → 403 (BLOCKED) + auto-blocklist
- **Otherwise** → ALLOW (forward)

### Egress
- **Egress Score ≥ 0.85** → 451 (DENIED)
- **Otherwise** → ALLOW (return backend response)

---

## Confidence Calculation

```
confidence = (header_score × 0.30) 
           + (body_score   × 0.35) 
           + (gru_score    × 0.25) 
           + (entropy_score × 0.10)
```

All agent scores are in [0, 1] range.

---

## Severity Assignment

- **Critical**: SQLi, command injection, reverse shell, DDoS
- **High**: XSS, LFI, RFI, XXE, SSRF, egress exfiltration
- **Medium**: Other IDS matches
- **Low**: No detections or low confidence

---

## Event Schema (WebSocket)

All events broadcast to `ws://localhost:8000/ws/soc` follow:

```json
{
  "event": "threat_blocked | reply_denied | request_allowed | ids_alert | soar_action | kill_switch | agent_update",
  "timestamp": "ISO8601",
  "source_ip": "string",
  "attack_type": "sqli | xss | ddos | egress | unknown | none",
  "severity": "critical | high | medium | low",
  "phase": "CNN → SOAR | Egress | Proxy Forward",
  "agents": {
    "header_score": 0.0,
    "body_score": 0.0,
    "gru_score": 0.0,
    "entropy": 0.0
  },
  "confidence": 0.0,
  "action": "ALLOWED | BLOCKED | DENIED | ANALYZED",
  "message": "string"
}
```

---

## Microservices Split (Future)

Current: **Monolith** (single FastAPI process)

Proposed:
1. **Gateway Service**: `app/main.py` (proxy + minimal routing)
2. **IDS/SIEM Worker**: Message queue consumer for signature matching
3. **Agent Inference Pool**: gRPC service for CNN/GRU scoring
4. **SOAR Orchestrator**: Centralized decision service with policy engine
5. **Dashboard Backend**: WebSocket relay + REST API server

Communication: RabbitMQ / Redis Streams / Kafka

---

## Phase-2 Enhancements

- **Real PCAP capture**: `scapy` / `pyshark` integration
- **Training pipeline**: Scheduled model retraining on labeled data
- **Persistence**: PostgreSQL for events, Redis for blocklist
- **Alerting**: Email/Slack/PagerDuty integrations
- **Metrics**: Prometheus + Grafana dashboards
- **Rate limiting**: Token bucket per IP
- **TLS termination**: HTTPS proxy support
- **Clustering**: Multi-node proxy with shared state (Redis)

---

## Security Considerations

- **Attack scripts are localhost-only by default** (env var override required)
- **Model is synthetic-trained** (production needs real labeled data)
- **No authentication on API endpoints** (add auth middleware for production)
- **In-memory state** (not persistent across restarts)
- **Single-threaded SIEM** (thread-safe but may bottleneck under heavy load)
- **No input sanitization on blocklist endpoints** (add IP validation)

---

## Performance Notes

- **Throughput**: ~500-1000 req/s on single CPU core (proxy overhead)
- **Latency**: +10-50ms per request (agent inference)
- **Model inference**: ~5-10ms on CPU (can offload to GPU for >10k req/s)
- **SIEM memory**: ~20k events × 1KB ≈ 20MB RAM

---

## Directory Map

```
app/
├── main.py              ← FastAPI app + proxy logic
├── config.py            ← Settings (env vars)
├── agents/              ← AI inference modules
│   ├── cnn_model.py     ← PyTorch model definition
│   ├── header_agent.py  ← HTTP header scorer
│   ├── body_agent.py    ← Request body scorer
│   ├── gru_agent.py     ← Temporal tracking
│   ├── entropy_agent.py ← Entropy normalization
│   └── egress_agent.py  ← Response scorer
├── pipeline/            ← Detection & response
│   ├── pcap_capture.py  ← Feature extraction
│   ├── ids_engine.py    ← Signature matching
│   ├── siem.py          ← Event store + blocklist
│   └── soar.py          ← Policy engine
└── api/                 ← HTTP + WebSocket interface
    ├── routes.py        ← REST endpoints
    └── websocket.py     ← SOC dashboard stream

scripts/
├── train_model.py       ← Model training
├── attack_*.py          ← Demo scripts
└── _common.py           ← Safety guardrails
```
