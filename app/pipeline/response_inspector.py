from __future__ import annotations

import json
import math
import re
from typing import Any


class ResponseInspector:
    """Inspect HTTP responses for egress threats and data exfiltration."""

    # Sensitive field patterns
    SENSITIVE_PATTERNS = {
        "password": re.compile(r'["\']?password["\']?\s*[:=]', re.IGNORECASE),
        "credit_card": re.compile(r'["\']?(?:cc|credit_card|card_number)["\']?\s*[:=]|(\d{4}[\s-]?){3}\d{4}', re.IGNORECASE),
        "ssn": re.compile(r'["\']?(?:ssn|social_security)["\']?\s*[:=]|(\d{3}[\s-]?){2}\d{4}', re.IGNORECASE),
        "api_key": re.compile(r'["\']?(?:api_key|apikey|secret)["\']?\s*[:=]', re.IGNORECASE),
        "token": re.compile(r'["\']?(?:token|auth|bearer)["\']?\s*[:=]', re.IGNORECASE),
        "private_key": re.compile(r'["\']?(?:private_key|private|secret_key)["\']?\s*[:=]', re.IGNORECASE),
    }

    # Information disclosure patterns
    INFO_DISCLOSURE_PATTERNS = {
        "path_traversal": re.compile(r'(?:\/etc\/|\/var\/|c:\\|windows\\|passwd|shadow|config)', re.IGNORECASE),
        "stack_trace": re.compile(r'(?:Traceback|File\s+\".*?\".*?line|At line|Stack trace)', re.IGNORECASE),
        "sql_error": re.compile(r'(?:SQL syntax|mysql_|postgresql_|ORA-|SQL Server)', re.IGNORECASE),
        "source_code": re.compile(r'(?:def\s+\w+|function\s+\w+|class\s+\w+|import\s+\w+)', re.IGNORECASE),
        "database_data": re.compile(r'(?:user_id|password_hash|secret_key|private_|internal_)', re.IGNORECASE),
    }

    # Header injection patterns
    HEADER_INJECTION_PATTERNS = {
        "open_redirect": re.compile(r'^(?:Location|Refresh):\s*(?:javascript:|data:|(?:https?:)?//)', re.IGNORECASE | re.MULTILINE),
        "xss_header": re.compile(r'<script|onerror|onload|javascript:', re.IGNORECASE),
        "header_injection": re.compile(r'\\r|\\n|%0d|%0a', re.IGNORECASE),
        "cache_poisoning": re.compile(r'(?:^Cache-Control|^Set-Cookie).*(?:max-age=0|expires=)', re.IGNORECASE | re.MULTILINE),
    }

    def __init__(self, max_response_size: int = 10485760):  # 10MB default
        self.max_response_size = max_response_size

    def inspect_response(
        self,
        status_code: int,
        headers: dict[str, str],
        body: bytes,
        request_size: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Inspect HTTP response for threats.
        Returns list of threat alerts.
        """
        alerts: list[dict[str, Any]] = []

        # Check 1: Response size anomaly
        size_alerts = self._check_response_size(len(body), request_size)
        alerts.extend(size_alerts)

        # Check 2: Sensitive field disclosure
        sensitive_alerts = self._check_sensitive_fields(body)
        alerts.extend(sensitive_alerts)

        # Check 3: Information disclosure patterns
        info_alerts = self._check_info_disclosure(body)
        alerts.extend(info_alerts)

        # Check 4: Header injection/manipulation
        header_alerts = self._check_headers(headers)
        alerts.extend(header_alerts)

        # Check 5: Entropy analysis (encrypted/stolen data)
        entropy_alerts = self._check_entropy(body)
        alerts.extend(entropy_alerts)

        # Check 6: Status code anomalies
        status_alerts = self._check_status_code(status_code, len(body))
        alerts.extend(status_alerts)

        return alerts

    def _check_response_size(self, response_size: int, request_size: int | None) -> list[dict[str, Any]]:
        """Detect anomalous response sizes (data exfiltration)."""
        alerts: list[dict[str, Any]] = []

        if response_size > self.max_response_size:
            alerts.append(
                {
                    "event": "ids_alert",
                    "attack_type": "exfiltration",
                    "severity": "critical",
                    "message": f"Response exceeds size limit: {response_size} bytes",
                    "details": {"response_size": response_size, "limit": self.max_response_size},
                }
            )

        # If request was small but response is huge, likely exfiltration
        if request_size and response_size > request_size * 100:
            alerts.append(
                {
                    "event": "ids_alert",
                    "attack_type": "exfiltration",
                    "severity": "high",
                    "message": f"Response size {response_size}B >> Request size {request_size}B (possible data exfiltration)",
                    "details": {"response_size": response_size, "request_size": request_size, "ratio": response_size / request_size},
                }
            )

        return alerts

    def _check_sensitive_fields(self, body: bytes) -> list[dict[str, Any]]:
        """Detect sensitive fields in response."""
        alerts: list[dict[str, Any]] = []

        try:
            body_text = body.decode("utf-8", errors="ignore")
        except Exception:
            return alerts

        found_fields = set()
        for field_name, pattern in self.SENSITIVE_PATTERNS.items():
            if pattern.search(body_text):
                found_fields.add(field_name)

        if found_fields:
            alerts.append(
                {
                    "event": "ids_alert",
                    "attack_type": "information_disclosure",
                    "severity": "critical",
                    "message": f"Sensitive fields exposed in response: {', '.join(sorted(found_fields))}",
                    "details": {"fields": sorted(found_fields)},
                }
            )

        return alerts

    def _check_info_disclosure(self, body: bytes) -> list[dict[str, Any]]:
        """Detect information disclosure patterns."""
        alerts: list[dict[str, Any]] = []

        try:
            body_text = body.decode("utf-8", errors="ignore")
        except Exception:
            return alerts

        found_patterns = set()
        for pattern_name, pattern in self.INFO_DISCLOSURE_PATTERNS.items():
            if pattern.search(body_text):
                found_patterns.add(pattern_name)

        if found_patterns:
            severity = "critical" if any(p in ["path_traversal", "stack_trace", "sql_error"] for p in found_patterns) else "high"
            alerts.append(
                {
                    "event": "ids_alert",
                    "attack_type": "information_disclosure",
                    "severity": severity,
                    "message": f"Information disclosure detected: {', '.join(sorted(found_patterns))}",
                    "details": {"patterns": sorted(found_patterns)},
                }
            )

        return alerts

    def _check_headers(self, headers: dict[str, str]) -> list[dict[str, Any]]:
        """Detect malicious headers."""
        alerts: list[dict[str, Any]] = []

        headers_text = "\n".join(f"{k}: {v}" for k, v in headers.items())

        found_attacks = set()
        for attack_name, pattern in self.HEADER_INJECTION_PATTERNS.items():
            if pattern.search(headers_text):
                found_attacks.add(attack_name)

        if found_attacks:
            severity = "critical" if "open_redirect" in found_attacks else "high"
            alerts.append(
                {
                    "event": "ids_alert",
                    "attack_type": "header_injection",
                    "severity": severity,
                    "message": f"Malicious headers detected: {', '.join(sorted(found_attacks))}",
                    "details": {"attacks": sorted(found_attacks)},
                }
            )

        return alerts

    def _check_entropy(self, body: bytes) -> list[dict[str, Any]]:
        """Detect high entropy (encrypted/stolen data)."""
        alerts: list[dict[str, Any]] = []

        if len(body) < 16:
            return alerts

        entropy = self._calculate_entropy(body[:4096])  # Check first 4KB

        if entropy > 7.5:
            alerts.append(
                {
                    "event": "ids_alert",
                    "attack_type": "exfiltration",
                    "severity": "high",
                    "message": f"High entropy in response ({entropy:.2f}) - possible encrypted/binary stolen data",
                    "details": {"entropy": round(entropy, 4), "chunk_size": min(4096, len(body))},
                }
            )

        return alerts

    def _check_status_code(self, status_code: int, response_size: int) -> list[dict[str, Any]]:
        """Detect suspicious status codes."""
        alerts: list[dict[str, Any]] = []

        # Server error with huge body (possible info leak)
        if 500 <= status_code < 600 and response_size > 10000:
            alerts.append(
                {
                    "event": "ids_alert",
                    "attack_type": "information_disclosure",
                    "severity": "high",
                    "message": f"Server error ({status_code}) with unusually large response body ({response_size}B) - possible stack trace/debug info",
                    "details": {"status_code": status_code, "response_size": response_size},
                }
            )

        # Weird redirect chains
        if status_code in [301, 302, 303, 307, 308] and response_size > 5000:
            alerts.append(
                {
                    "event": "ids_alert",
                    "attack_type": "suspicious_redirect",
                    "severity": "medium",
                    "message": f"Redirect ({status_code}) with suspicious body size ({response_size}B)",
                    "details": {"status_code": status_code, "response_size": response_size},
                }
            )

        return alerts

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        entropy = 0.0
        data_len = len(data)
        for count in byte_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)

        return entropy
