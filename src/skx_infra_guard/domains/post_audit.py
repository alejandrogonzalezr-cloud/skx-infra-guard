"""Credential-in-output detection.

PostToolUse only: this can never block (the tool already ran), it can only 
flag for the Audit Engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_CREDENTIAL_PATTERNS: list[tuple[str, str]] = [
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("aws_secret_key", r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}"),
    ("jwt", r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    ("github_pat_classic", r"ghp_[A-Za-z0-9]{36}"),
    ("github_pat_fine_grained", r"github_pat_[A-Za-z0-9_]{82}"),
    ("openai_key", r"sk-[A-Za-z0-9]{48}"),
    ("anthropic_key", r"sk-ant-[A-Za-z0-9_-]{90,}"),
    ("ssh_private_key", r"-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) PRIVATE KEY-----"),
    ("generic_secret", r"(password|passwd|token|secret|api_key|apikey|auth_token)\s*[=:]\s*['\"]?[A-Za-z0-9/+_-]{20,}['\"]?"),
    ("stripe_key", r"(sk|pk|rk)_(live|test)_[A-Za-z0-9]{24}"),
    ("slack_token", r"xox[bpoas]-[A-Za-z0-9-]+"),
]


@dataclass
class CredentialHit:
    credential_type: str


def scan(output: str) -> list[CredentialHit]:
    hits = []
    for name, pattern in _CREDENTIAL_PATTERNS:
        if re.search(pattern, output):
            hits.append(CredentialHit(credential_type=name))
    return hits
