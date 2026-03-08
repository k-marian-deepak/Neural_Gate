from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from app.agents.body_agent import BodyAgent
from app.agents.cnn_model import InferenceModel
from app.agents.egress_agent import EgressAgent
from app.agents.entropy_agent import EntropyAgent
from app.agents.gru_agent import GRUTemporalAgent
from app.agents.header_agent import HeaderAgent
from app.api.routes import build_api_router
from app.api.websocket import SOCWebSocketManager, build_ws_router
from app.config import settings
from app.pipeline.ids_engine import IDSEngine
from app.pipeline.pcap_capture import CaptureAdapter
from app.pipeline.adaptive_policy import AdaptivePolicy
from app.pipeline.response_inspector import ResponseInspector
from app.pipeline.siem import SIEMStore
from app.pipeline.soar import SOAREngine


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
}


@dataclass
class RuntimeState:
    siem: SIEMStore
    ws: SOCWebSocketManager
    ids: IDSEngine
    soar: SOAREngine
    capture: CaptureAdapter
    header_agent: HeaderAgent
    body_agent: BodyAgent
    gru_agent: GRUTemporalAgent
    entropy_agent: EntropyAgent
    egress_agent: EgressAgent
    response_inspector: ResponseInspector
    adaptive: AdaptivePolicy
    last_agent_scores: dict[str, Any] = field(default_factory=dict)


def build_state() -> RuntimeState:
    siem = SIEMStore(blocklist_persist_path=settings.blocklist_persist_path)
    ws = SOCWebSocketManager()
    model = InferenceModel(settings.model_path)
    return RuntimeState(
        siem=siem,
        ws=ws,
        ids=IDSEngine(settings.ddos_window_seconds, settings.ddos_max_requests),
        soar=SOAREngine(siem),
        capture=CaptureAdapter(),
        header_agent=HeaderAgent(model),
        body_agent=BodyAgent(model),
        gru_agent=GRUTemporalAgent(),
        entropy_agent=EntropyAgent(),
        egress_agent=EgressAgent(model),
        response_inspector=ResponseInspector(max_response_size=50 * 1024 * 1024),  # 50MB limit
        adaptive=AdaptivePolicy(
            enabled=settings.enable_adaptive_learning,
            learning_rate=settings.adaptive_learning_rate,
            influence=settings.adaptive_influence,
            max_memory=settings.adaptive_memory_size,
            persist_path=settings.adaptive_persist_path,
            autosave_every=settings.adaptive_autosave_every,
        ),
    )


def get_source_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def choose_severity(ids_alerts: list[dict[str, Any]], confidence: float) -> str:
    if any(alert.get("severity") == "critical" for alert in ids_alerts) or confidence >= 0.95:
        return "critical"
    if any(alert.get("severity") in {"high", "critical"} for alert in ids_alerts) or confidence >= 0.85:
        return "high"
    if confidence >= 0.6:
        return "medium"
    return "low"


async def emit_event(state: RuntimeState, payload: dict[str, Any]) -> None:
    payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    state.siem.add_event(payload)
    await state.ws.broadcast(payload)


app = FastAPI(title="Neural Gate", version="2026")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.state.runtime = build_state()


@app.on_event("startup")
async def startup_event():
    """Application startup"""
    print(f"[Neural-Gate] Starting up...")
    print(f"[Neural-Gate] Target server: {settings.target_server}")
    print(f"[Neural-Gate] Phase 2 PCAP: {'ENABLED' if settings.enable_phase2_pcap else 'DISABLED'}")
    if settings.enable_phase2_pcap:
        print(f"[Neural-Gate] PCAP Interface: {settings.pcap_interface}")
        print(f"[Neural-Gate] PCAP Filter: {settings.pcap_filter}")
    print(f"[Neural-Gate] Adaptive Learning: {'ENABLED' if settings.enable_adaptive_learning else 'DISABLED'}")


@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown - clean up PCAP capture"""
    print("[Neural-Gate] Shutting down...")
    state = _state()
    if hasattr(state.capture, 'shutdown'):
        state.capture.shutdown()
    if hasattr(state.adaptive, "shutdown"):
        state.adaptive.shutdown()
    print("[Neural-Gate] Shutdown complete")


def _state() -> RuntimeState:
    return app.state.runtime


app.include_router(build_api_router(_state))
app.include_router(build_ws_router(lambda: _state().ws))


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


def _proxy_target(full_path: str, query: str) -> str:
    base = settings.target_server.rstrip("/")
    path = full_path.lstrip("/")
    url = f"{base}/{path}"
    if query:
        url = f"{url}?{query}"
    return url


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def proxy_all(full_path: str, request: Request):
    # Skip Neural-Gate's own API routes (they're already registered)
    # This prevents infinite loops on /api/*, /ws/*, /health
    # But we DO want to proxy backend routes like /api/login -> backend
    
    state = _state()
    source_ip = get_source_ip(request)

    # ==== BLOCKLIST CHECK - FIRST LINE OF DEFENSE (instant, before any processing) ====
    if state.siem.is_ip_blocked(source_ip):
        await emit_event(
            state,
            {
                "event": "threat_blocked",
                "source_ip": source_ip,
                "attack_type": "blocklist_hit",
                "severity": "high",
                "phase": "Blocklist (Early Exit)",
                "confidence": 1.0,
                "action": "BLOCKED",
                "message": f"IP {source_ip} is blocklisted (instant rejection)",
            },
        )
        return JSONResponse(
            {"detail": "Your IP is blocklisted. Request rejected."},
            status_code=403,
        )

    # ==== KILL SWITCH CHECK - SECOND LINE OF DEFENSE ====
    if state.siem.kill_switch_enabled:
        return JSONResponse(
            {"detail": "Service unavailable (kill switch active)"},
            status_code=503,
        )

    body = await request.body()
    body_for_analysis = body[: settings.max_body_bytes]
    headers = {k: v for k, v in request.headers.items()}

    features = state.capture.extract_request_features(request.method, request.url.path, headers, body_for_analysis)
    body_text = body_for_analysis.decode("utf-8", errors="ignore")

    ids_alerts = state.ids.inspect(source_ip, request.method, request.url.path, headers, body_text)
    for alert in ids_alerts:
        await emit_event(state, alert)

    header_score = state.header_agent.score(headers, request.url.path)
    body_score = state.body_agent.score(body_for_analysis)
    entropy_score = state.entropy_agent.score(float(features["entropy"]))
    gru_score = state.gru_agent.score(source_ip, max(header_score, body_score))

    confidence = min(max((header_score * 0.30) + (body_score * 0.35) + (gru_score * 0.25) + (entropy_score * 0.10), 0.0), 1.0)
    fingerprint, tokens = state.adaptive.fingerprint(request.method, request.url.path, body_text)
    adjusted_confidence, adaptive_info = state.adaptive.adjust_confidence(confidence, fingerprint, tokens)
    severity = choose_severity(ids_alerts, adjusted_confidence)

    state.last_agent_scores = {
        "header_score": round(header_score, 4),
        "body_score": round(body_score, 4),
        "gru_score": round(gru_score, 4),
        "entropy": round(float(features["entropy"]), 4),
        "entropy_score": round(entropy_score, 4),
        "base_confidence": round(confidence, 4),
        "confidence": round(adjusted_confidence, 4),
        "adaptive": adaptive_info,
    }

    await emit_event(
        state,
        {
            "event": "agent_update",
            "source_ip": source_ip,
            "phase": "CNN → SOAR",
            "agents": {
                "header_score": header_score,
                "body_score": body_score,
                "gru_score": gru_score,
                "entropy": float(features["entropy"]),
            },
            "confidence": adjusted_confidence,
            "action": "ANALYZED",
            "message": "Agent scores updated",
        },
    )

    decision = state.soar.decide_request_action(source_ip, ids_alerts, adjusted_confidence, severity)
    state.adaptive.learn(
        fingerprint=fingerprint,
        ids_alert_count=len(ids_alerts),
        action=decision["action"],
        confidence=adjusted_confidence,
    )
    if decision["action"] != "ALLOWED":
        attack_type = ids_alerts[0].get("attack_type") if ids_alerts else "unknown"
        await emit_event(
            state,
            {
                "event": decision["event"],
                "source_ip": source_ip,
                "attack_type": attack_type,
                "severity": decision["severity"],
                "phase": "CNN → SOAR",
                "agents": {
                    "header_score": header_score,
                    "body_score": body_score,
                    "gru_score": gru_score,
                    "entropy": float(features["entropy"]),
                    "adaptive": adaptive_info,
                },
                "confidence": adjusted_confidence,
                "action": decision["action"],
                "message": decision["reason"],
            },
        )
        status = 503 if decision["event"] == "kill_switch" else 403
        return JSONResponse({"detail": decision["reason"], "action": decision["action"]}, status_code=status)

    outbound_headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
    outbound_url = _proxy_target(full_path, request.url.query)

    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds, follow_redirects=False) as client:
            upstream = await client.request(
                request.method,
                outbound_url,
                headers=outbound_headers,
                content=body,
            )
    except httpx.RequestError as exc:
        await emit_event(
            state,
            {
                "event": "reply_denied",
                "source_ip": source_ip,
                "attack_type": "proxy_error",
                "severity": "high",
                "phase": "Egress",
                "confidence": 1.0,
                "action": "DENIED",
                "message": f"Upstream connection failed: {exc.__class__.__name__}",
            },
        )
        return JSONResponse({"detail": "Upstream request failed"}, status_code=502)

    upstream_content = upstream.content
    resp_features = state.capture.extract_response_features(upstream.status_code, dict(upstream.headers), upstream_content)
    egress_score = state.egress_agent.score(upstream_content[: settings.max_body_bytes], float(resp_features["entropy"]))

    # ==== RESPONSE INSPECTION (Check for egress threats, exfiltration, data leaks) ====
    response_threats = state.response_inspector.inspect_response(
        status_code=upstream.status_code,
        headers=dict(upstream.headers),
        body=upstream_content,
        request_size=len(body),
    )

    # Log response threat alerts
    for threat in response_threats:
        await emit_event(
            state,
            {
                "event": threat.get("event", "ids_alert"),
                "source_ip": source_ip,
                "attack_type": threat.get("attack_type", "egress_threat"),
                "severity": threat.get("severity", "medium"),
                "phase": "Egress (Response Inspector)",
                "confidence": 0.9 if threat.get("severity") == "critical" else 0.7,
                "action": "DETECTED",
                "message": threat.get("message", "Response threat detected"),
                "details": threat.get("details", {}),
            },
        )

    # If critical response threats detected, block the response
    if any(t.get("severity") == "critical" for t in response_threats):
        await emit_event(
            state,
            {
                "event": "reply_denied",
                "source_ip": source_ip,
                "attack_type": "response_threat",
                "severity": "critical",
                "phase": "Egress (Response Inspector)",
                "confidence": 1.0,
                "action": "BLOCKED",
                "message": "Response blocked due to critical egress threat detection",
            },
        )
        return JSONResponse(
            {"detail": "Response integrity check failed - critical egress threat detected"},
            status_code=451,
        )

    egress_decision = state.soar.decide_response_action(egress_score)
    if egress_decision["action"] == "DENIED":
        await emit_event(
            state,
            {
                "event": "reply_denied",
                "source_ip": source_ip,
                "attack_type": "egress",
                "severity": egress_decision["severity"],
                "phase": "Egress Reply Inspector",
                "agents": state.last_agent_scores,
                "confidence": egress_score,
                "action": "DENIED",
                "message": egress_decision["reason"],
            },
        )
        return JSONResponse({"detail": egress_decision["reason"]}, status_code=451)

    await emit_event(
        state,
        {
            "event": "request_allowed",
            "source_ip": source_ip,
            "attack_type": "none",
            "severity": "low",
            "phase": "Proxy Forward",
            "agents": state.last_agent_scores,
            "confidence": max(confidence, 1.0 - egress_score),
            "action": "ALLOWED",
            "message": "Traffic forwarded",
        },
    )

    headers = {k: v for k, v in upstream.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
    return Response(content=upstream_content, status_code=upstream.status_code, headers=headers)
