# Challenges I Ran Into

Building Neural-Gate involved several technical hurdles. Here's how I solved them.

---

## 1. Blocklist State Loss Across Restarts

**Problem:** In-memory IP blocklist was wiped on restart—attackers could retry malicious payloads after a reboot.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant NG as Neural-Gate
    participant BL as In-Memory Blocklist
    
    A->>NG: Malicious Request #1
    NG->>BL: Check IP
    BL-->>NG: Not blocked
    NG->>NG: Detect threat
    NG->>BL: Block IP (in memory)
    NG-->>A: 403 Blocked
    
    Note over NG,BL: System Restart
    BL->>BL: ❌ Blocklist wiped
    
    A->>NG: Same Malicious Request
    NG->>BL: Check IP
    BL-->>NG: Not blocked ⚠️
    NG-->>A: ✓ Request passes
```

**Solution:** Added atomic JSON persistence (`_persist_blocklist()`) with temp-file writes and expiry-aware loading on SIEM init. Blocked IPs now survive restarts.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant NG as Neural-Gate
    participant BL as Persistent Blocklist
    participant F as JSON File
    
    A->>NG: Malicious Request #1
    NG->>BL: Check IP
    BL->>F: Load from disk
    F-->>BL: Empty or expired entries
    BL-->>NG: Not blocked
    NG->>NG: Detect threat
    NG->>BL: Block IP
    BL->>F: Atomic save (tmp → replace)
    NG-->>A: 403 Blocked
    
    Note over NG,F: System Restart
    
    A->>NG: Same Malicious Request
    NG->>BL: Check IP
    BL->>F: Load from disk
    F-->>BL: IP found, not expired
    BL-->>NG: ✓ Blocked
    NG-->>A: 403 Blocked (instant)
```

---

## 2. CNN + ReLU Activation for Binary Traffic Classification

**Problem:** Needed a neural architecture that could detect malicious byte patterns in HTTP payloads, but traditional dense layers couldn't capture spatial features in raw traffic.

**Solution:** Built a **Conv1D → ReLU → MaxPool** pipeline with 3 stacked layers (32→64→128 filters) to extract hierarchical byte-level patterns. ReLU activation was critical—it introduced non-linearity to learn complex attack signatures while keeping inference fast (~15-25ms). Combined with BiGRU for temporal context.

```mermaid
graph LR
    subgraph Input
    P[HTTP Payload<br/>1024 bytes]
    end
    
    subgraph CNN Pipeline
    P --> C1[Conv1D: 1→32<br/>kernel=8]
    C1 --> R1[ReLU]
    R1 --> M1[MaxPool1d: 4]
    M1 --> C2[Conv1D: 32→64<br/>kernel=4]
    C2 --> R2[ReLU]
    R2 --> M2[MaxPool1d: 4]
    M2 --> C3[Conv1D: 64→128<br/>kernel=3]
    C3 --> R3[ReLU]
    R3 --> AP[AdaptiveAvgPool]
    end
    
    subgraph Temporal
    AP --> GRU[BiGRU<br/>128→64x2]
    end
    
    subgraph Output
    GRU --> D[Dropout 0.4]
    D --> L[Linear 128→1]
    L --> S[Sigmoid]
    S --> O[Threat Score<br/>0.0-1.0]
    end
    
    style R1 fill:#f96
    style R2 fill:#f96
    style R3 fill:#f96
```

**Result:** Achieved sub-30ms inference with strong precision on SQLi, XSS, and exfiltration patterns.

---

## 3. AI Model Inference Latency in Inline Proxy

**Problem:** PyTorch CNN+BiGRU added ~80-120ms latency per request—too slow for production proxy.

**Solution:** Used `model.eval()` + `torch.no_grad()`, limited payload to 1024 bytes, pre-allocated tensors. Added entropy-based fallback if PyTorch unavailable.

```mermaid
flowchart LR
    subgraph Before["❌ Before Optimization"]
    R1[Request] --> T1[Convert to Tensor<br/>Full payload]
    T1 --> M1[Model Inference<br/>Gradient tracking ON]
    M1 --> D1[Decision<br/>~80-120ms]
    end
    
    subgraph After["✅ After Optimization"]
    R2[Request] --> T2[Convert to Tensor<br/>1024 bytes max]
    T2 --> M2[model.eval<br/>torch.no_grad]
    M2 --> D2[Decision<br/>~15-25ms]
    end
    
    style Before fill:#fee
    style After fill:#efe
```

**Result:** Dropped to 15-25ms, making inline AI practical.

---

## 4. Packet Capture Requiring Root (PCAP)

**Problem:** Scapy needs `CAP_NET_RAW`—running FastAPI as root is unsafe.

**Solution:** Used Linux capabilities (`setcap cap_net_raw,cap_net_admin=eip`) on Python binary. Made PCAP optional with graceful HTTP-level fallback.

```mermaid
flowchart TB
    subgraph Bad["❌ Security Anti-Pattern"]
    S1[sudo uvicorn app.main:app]
    S1 --> F1[FastAPI runs as ROOT]
    F1 --> P1[PCAP works ✓]
    F1 --> R1[Security Risk ⚠️]
    end
    
    subgraph Good["✅ Capability-Based Approach"]
    S2[setcap cap_net_raw<br/>on Python binary]
    S2 --> F2[FastAPI runs as USER]
    F2 --> P2[PCAP works ✓]
    F2 --> R2[No root needed ✓]
    S2 -.fallback.-> F3[PCAP disabled?<br/>HTTP-level features]
    end
    
    style Bad fill:#fee
    style Good fill:#efe
```

**Result:** Standard users run proxy mode; PCAP is opt-in for deep visibility.

---

## 5. Race Conditions in Concurrent Blocklist Access

**Problem:** Async FastAPI caused concurrent blocklist updates, double-blocking, and inconsistent reads.

**Solution:** Added `threading.Lock()` around all blocklist mutations. Prepared data in lock, persisted outside.

```mermaid
sequenceDiagram
    participant R1 as Request 1
    participant R2 as Request 2
    participant BL as Blocklist Dict
    participant F as File
    
    Note over R1,R2: ❌ Race Condition
    R1->>BL: Read blocklist
    R2->>BL: Read blocklist (same time)
    R1->>BL: Add IP A
    R2->>BL: Add IP B
    R1->>F: Save (IP A only)
    R2->>F: Save (IP B only) ⚠️ Lost IP A
    
    Note over R1,R2: ✅ With Lock
    R1->>BL: Acquire Lock
    R1->>BL: Add IP A
    R1->>F: Save
    R1->>BL: Release Lock
    R2->>BL: Acquire Lock
    R2->>BL: Add IP B
    R2->>F: Save (both IPs)
    R2->>BL: Release Lock
```

**Result:** Atomic, race-free blocklist operations.

---

## 6. Balancing False Positives vs. False Negatives

**Problem:** Static threshold (`confidence >= 0.85`) either blocked legit traffic or missed attacks.

**Solution:** Multi-agent fusion (CNN + GRU + entropy + IDS). Added adaptive learning layer—analysts can mark patterns as `legit`/`malicious` via API, adjusting future scores.

```mermaid
flowchart TB
    R[Request] --> H[Header Agent]
    R --> B[Body Agent<br/>CNN]
    R --> E[Entropy Agent]
    R --> G[GRU Temporal]
    R --> I[IDS Engine]
    
    H --> F[Fusion Layer<br/>Weighted Sum]
    B --> F
    E --> F
    G --> F
    
    F --> A[Adaptive Policy<br/>Adjust by feedback]
    I --> A
    
    A --> D{SOAR Decision}
    D -->|High confidence| BL[BLOCK]
    D -->|Critical IDS alert| BL
    D -->|Low confidence| AL[ALLOW]
    
    BL -.feedback.-> FB[(Analyst<br/>Feedback API)]
    AL -.feedback.-> FB
    FB -.learn.-> A
    
    style F fill:#9cf
    style A fill:#fc9
    style FB fill:#9f9
```

**Result:** Reduced false positives significantly while maintaining detection coverage.

---

## 7. WebSocket Connection Stability (SOC Dashboard)

**Problem:** Stale WebSocket connections caused memory leaks and broadcast failures.

**Solution:** Added exception handling in `broadcast()`, stale connection cleanup, and `asyncio.gather(..., return_exceptions=True)`.

```mermaid
sequenceDiagram
    participant C1 as Client 1
    participant C2 as Client 2 (stale)
    participant C3 as Client 3
    participant BC as Broadcast Manager
    
    Note over BC: Event: "threat_blocked"
    
    BC->>C1: send_json(event)
    C1-->>BC: ✓ OK
    
    BC->>C2: send_json(event)
    C2--xBC: ❌ Connection closed
    Note over BC: Mark C2 as stale
    
    BC->>C3: send_json(event)
    C3-->>BC: ✓ OK
    
    BC->>BC: Remove stale connections
    BC->>BC: C2 removed from pool
    
    Note over BC,C3: Next event continues safely
```

**Result:** Stable real-time event streaming to SOC dashboard.

---

## Key Takeaway

Inline security products need **defense in depth everywhere**: model optimization, state management, concurrency control, and graceful degradation. Every layer must handle failure cleanly.
