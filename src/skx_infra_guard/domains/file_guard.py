"""File read/write protection.

Applies to Write/Edit/MultiEdit (blocks writes to protected paths) and 
Read (blocks reads of sensitive credential files). Not environment-gated, 
as a private key is sensitive in every environment.
"""

from __future__ import annotations

import os
import re

from skx_infra_guard.core.decision import Decision, EnvironmentTier, RiskLevel, Verdict

DOMAIN = "file"

_PROTECTED_WRITE_PATTERNS = [
    r"^/etc/",
    r"^/usr/bin/",
    r"^/usr/sbin/",
    r"^/usr/lib/",
    r"^/bin/",
    r"^/sbin/",
    r"^/boot/",
    r"^/sys/",
    r"^/proc/",
    r"^/dev/",
    r"^/var/log/",
    r"\.ssh/(authorized_keys|id_rsa|id_ed25519|id_ecdsa|id_dsa|known_hosts|config)$",
    r"\.ssh/.*\.(pub|pem|key)$",
    r"\.aws/credentials$",
    r"\.aws/config$",
    r"\.kube/config$",
    r"\.docker/config\.json$",
    r"\.npmrc$",
    r"\.pypirc$",
    r"\.netrc$",
    r"\.git-credentials$",
    r"secrets\.(json|yaml|yml|env)$",
    r"credentials\.(json|yaml|yml)$",
    r"\.(pem|p12|pfx|key)$",
    r"\.tfstate(\.backup)?$",  # ported from infra-guard.sh — state must only
    # be touched by terraform itself
]

_SENSITIVE_READ_PATTERNS = [
    r"\.env(\.local|\.production|\.staging|\.test)?$",
    r"/etc/shadow$",
    r"/etc/gshadow$",
    r"/etc/master\.passwd$",
    r"\.ssh/id_(rsa|ed25519|ecdsa|dsa)$",
    r"\.ssh/authorized_keys$",
    r"\.aws/credentials$",
    r"\.kube/config$",
    r"\.docker/config\.json$",
    r"\.npmrc$",
    r"\.pypirc$",
    r"\.netrc$",
    r"\.git-credentials$",
    r"/proc/self/environ$",
    r"/proc/\d+/environ$",
    r"\.(pem|p12|pfx|key)$",
    r"secrets\.json$",
    r"credentials\.json$",
]


def _expand(path: str) -> str:
    return os.path.expanduser(path)


def check_write(path: str) -> str | None:
    expanded = _expand(path)
    for pattern in _PROTECTED_WRITE_PATTERNS:
        if re.search(pattern, expanded, re.IGNORECASE):
            return pattern
    return None


def check_read(path: str) -> str | None:
    expanded = _expand(path)
    for pattern in _SENSITIVE_READ_PATTERNS:
        if re.search(pattern, expanded, re.IGNORECASE):
            return pattern
    return None


def evaluate_write(paths: list[str], environment: EnvironmentTier) -> Verdict | None:
    for path in paths:
        pattern = check_write(path)
        if pattern is not None:
            return Verdict(
                decision=Decision.BLOCK,
                reason=f"writing to protected path is not allowed: {path} (pattern: {pattern})",
                risk=RiskLevel.CRITICAL,
                domain=DOMAIN,
                rule_id="file.protected_write",
                resource=path,
                environment=environment,
            )
    return None


def evaluate_read(paths: list[str], environment: EnvironmentTier) -> Verdict | None:
    for path in paths:
        pattern = check_read(path)
        if pattern is not None:
            return Verdict(
                decision=Decision.BLOCK,
                reason=f"reading a sensitive credential file is not allowed: {path}",
                risk=RiskLevel.CRITICAL,
                domain=DOMAIN,
                rule_id="file.sensitive_read",
                resource=path,
                environment=environment,
            )
    return None
