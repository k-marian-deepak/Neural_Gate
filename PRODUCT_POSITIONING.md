# Neural-Gate Product Positioning

Neural-Gate is a **real-time AI cyber defense gateway** that sits in front of applications, inspects traffic continuously, and takes autonomous response actions to stop threats before they impact core services.

It is not only a safety testing utility. It is a complete product that combines **detection, decisioning, enforcement, and SOC visibility** in one deployable platform.

## The Problem It Solves

Modern security operations are often fragmented: one tool for alerting, another for logs, another for blocking, and manual response across each stage. This creates response delays, blind spots, and inconsistent enforcement.

Neural-Gate solves this by unifying the traffic security loop so teams can:

- Detect malicious behavior early (ingress and egress)
- Block or deny risky traffic in-line before backend impact
- Persist defense state against repeat offenders
- Monitor all security events in a SOC-style live workflow
- Operate faster with fewer manual handoffs

## What People Can Use It For

- **Security training labs**: run realistic red-team/blue-team attack simulations
- **Detection engineering**: validate whether model and policy updates catch attacks
- **SOC onboarding and demos**: demonstrate end-to-end detect → decide → respond
- **Pre-production hardening**: stress-test protection behavior before production rollout
- **Research and experimentation**: tune thresholds, adaptive learning, and response policy

## How It Makes Existing Tasks Easier and Safer

- Replaces ad-hoc testing with a **repeatable attack-validation pipeline**
- Reduces accidental exposure by enforcing a **controlled proxy security path**
- Accelerates triage with **centralized event context** instead of scattered logs
- Improves confidence through **persistent blocking of repeat malicious sources**
- Enables operational control through kill switch and blocklist APIs

## USP (Unique Product Strengths)

- **Inline AI Enforcement**: moves from passive alerting to active prevention
- **AI + Policy Fusion**: combines learned risk scoring with deterministic SOAR policy
- **Persistent Defense Memory**: blocked sources remain enforced across restarts
- **Full Visibility Stack**: event stream, threat scores, stats, and blocklist in one system
- **Operational Controls**: kill switch, blocklist management, policy-driven response
- **Flexible Deployment Modes**: supports proxy and transparent topologies

## Core Technology Stack (Built Product)

- **Language and runtime**: Python
- **AI framework**: PyTorch
- **Neural model architecture**: `Conv1D + ReLU + MaxPool + Conv1D + ReLU + MaxPool + Conv1D + ReLU + BiGRU + Dropout + Sigmoid`
- **Temporal behavior agent**: GRU-based rolling anomaly scoring per source
- **Security control pipeline**: IDS + SOAR decision engine (`ALLOW / BLOCK / DENY`)
- **API and proxy layer**: FastAPI + Uvicorn + HTTPX
- **Live SOC telemetry**: WebSocket event broadcasting
- **Packet-level visibility**: Scapy / PyShark (Phase 2 PCAP capture path)
- **Adaptive memory and persistence**: persisted adaptive state + persisted blocklist enforcement

## Why It Matters for Organizations

Neural-Gate helps security and platform teams become **faster, safer, and more autonomous** by reducing response latency, improving attack containment, and converting security from passive monitoring into an active control layer.

In practical terms, it provides a unified **Detect → Decide → Enforce → Observe** product workflow instead of disconnected tools.

## Product Visuals

### System Architecture Diagram

```mermaid
flowchart TB
		U[Clients / Attack Sources] --> NGIN[Ingress Interface\nPort 8000]

		subgraph NG[Neural-Gate Runtime]
			P[FastAPI Proxy Core]
			FE[Feature Extraction\nHeaders, Body, Entropy, Context]
			AI[AI Detection Layer\nPyTorch CNN + BiGRU]
			IDS[IDS Engine\nRule/Pattern + DDoS Signals]
			SOAR[SOAR Policy Engine\nALLOW / BLOCK / DENY]
			ENF[Inline Enforcement\n403/451/503 + Kill Switch]
			EG[Egress Inspector\nResponse Integrity Checks]
			SIEM[SIEM Event Store\nLogs, Stats, Counters]
			WS[WebSocket Broadcast\nLive SOC Feed]
			API[Control APIs\nBlocklist, Killswitch, Agents]
			BL[(Persistent Blocklist)]
			AD[(Adaptive Memory Store)]
		end

		NGIN --> P
		P --> FE
		FE --> AI
		FE --> IDS
		AI --> SOAR
		IDS --> SOAR
		SOAR -->|ALLOW| UP[Protected Backend\nVulnerable/Test App :3001]
		SOAR -->|BLOCK/DENY| ENF
		UP --> EG
		EG -->|Safe| R[Client Response]
		EG -->|Threat| ENF

		SOAR --> SIEM
		ENF --> SIEM
		EG --> SIEM
		SIEM --> WS
		API --> SIEM
		API --> BL
		API --> AD
		SOAR <--> BL
		AI <--> AD
```

### 1) Threat Decision Flow

```mermaid
flowchart LR
		A[Incoming Request] --> B[Feature Extraction]
		B --> C[AI Scoring\nCNN + GRU + Entropy]
		C --> D[IDS Alerts]
		D --> E[SOAR Policy Engine]
		E -->|ALLOW| F[Forward to Backend]
		E -->|BLOCK| G[Reject Request 403]
		E -->|DENY| H[Kill Switch / 503]
		G --> I[SIEM Event + Blocklist Update]
		H --> I
		F --> J[Egress Inspection]
		J -->|Safe| K[Response to Client]
		J -->|Threat| L[Reply Denied 451]
		L --> I
```

### 2) Product Architecture

```mermaid
flowchart TB
		C[Attacker / User Traffic] --> P[Neural-Gate Proxy\nFastAPI + Uvicorn]
		P --> M[AI Detection Layer\nPyTorch CNN + BiGRU]
		P --> I[IDS Engine]
		M --> S[SOAR Decision Layer]
		I --> S
		S -->|ALLOW| B[Vulnerable Backend / App]
		S -->|BLOCK or DENY| R[Inline Enforcement]
		P --> E[Egress Inspector]
		E --> T[Response Threat Detection]
		P --> W[WebSocket SOC Stream]
		P --> A[REST API\nStats / Logs / Blocklist]
		P --> D[Persistent Stores\nAdaptive Memory + Blocklist]
```

### 3) USP Map

```mermaid
mindmap
	root((Neural-Gate USPs))
		Inline AI Enforcement
			Real-time blocking
			Pre-backend threat stop
		AI + Policy Fusion
			CNN and BiGRU scoring
			Deterministic SOAR actions
		Persistent Defense Memory
			Repeat offender blocking
			Restart-safe blocklist
		Full SOC Visibility
			Live WebSocket events
			API-driven stats and logs
		Operational Control
			Kill switch
			Blocklist APIs
		Deployment Flexibility
			Proxy mode
			Transparent mode
```