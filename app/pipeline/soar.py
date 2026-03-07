from __future__ import annotations

from typing import Any

from app.config import settings
from app.pipeline.siem import SIEMStore


class SOAREngine:
    def __init__(self, siem: SIEMStore) -> None:
        self.siem = siem

    def decide_request_action(
        self,
        source_ip: str,
        ids_alerts: list[dict[str, Any]],
        confidence: float,
        severity: str,
    ) -> dict[str, Any]:
        if self.siem.kill_switch_enabled:
            return {
                "action": "DENIED",
                "reason": "Kill switch enabled",
                "event": "kill_switch",
                "severity": "critical",
            }

        # NOTE: Blocklist check now happens in proxy_all() as early exit before this decision
        # This call will never see blocked IPs (they're rejected immediately)
        
        critical_ids = any(alert.get("severity") == "critical" for alert in ids_alerts)
        if critical_ids or confidence >= settings.malicious_threshold:
            self.siem.block_ip(source_ip, settings.blocklist_ttl_seconds)
            return {
                "action": "BLOCKED",
                "reason": "Threat confidence exceeded threshold",
                "event": "threat_blocked",
                "severity": max(severity, "high"),
            }

        return {
            "action": "ALLOWED",
            "reason": "No blocking policy triggered",
            "event": "request_allowed",
            "severity": "low",
        }

    def decide_response_action(self, egress_score: float) -> dict[str, Any]:
        if egress_score >= settings.malicious_threshold:
            return {
                "action": "DENIED",
                "reason": "Egress reply deemed malicious",
                "event": "reply_denied",
                "severity": "high",
            }
        return {
            "action": "ALLOWED",
            "reason": "Egress reply passed inspection",
            "event": "request_allowed",
            "severity": "low",
        }
