"""WebFetch SSRF protection: cloud metadata endpoints, loopback,
RFC-1918 private ranges, IPv6 private ranges, and file:// URIs.
"""

from __future__ import annotations

import re

from skx_infra_guard.core.decision import Decision, EnvironmentTier, RiskLevel, Verdict

DOMAIN = "web"

_BLOCKED_PATTERNS: list[tuple[str, str]] = [
    (r"^file://", "file:// URIs are not allowed — use the Read tool for local files"),
    (r"169\.254\.169\.254", "cloud metadata endpoint (AWS/Azure/OpenStack) access is not allowed"),
    (r"metadata\.google\.internal", "GCP metadata endpoint access is not allowed"),
    (r"169\.254\.170\.2", "ECS task metadata endpoint access is not allowed"),
    (r"https?://(localhost|127\.\d+\.\d+\.\d+|::1)(:|/|$)", "loopback/localhost URLs are not allowed"),
    (r"https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}", "access to private network addresses (10.0.0.0/8) is not allowed"),
    (r"https?://172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}", "access to private network addresses (172.16.0.0/12) is not allowed"),
    (r"https?://192\.168\.\d{1,3}\.\d{1,3}", "access to private network addresses (192.168.0.0/16) is not allowed"),
    (r"https?://\[(f[ce][0-9a-f]{2}:|fe80:)", "access to private IPv6 addresses is not allowed"),
]


def evaluate(url: str, environment: EnvironmentTier) -> Verdict | None:
    for pattern, reason in _BLOCKED_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            return Verdict(
                decision=Decision.BLOCK,
                reason=reason,
                risk=RiskLevel.CRITICAL,
                domain=DOMAIN,
                rule_id="web.ssrf",
                resource=url,
                environment=environment,
            )
    return None
