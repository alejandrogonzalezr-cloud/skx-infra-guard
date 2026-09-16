"""Secrets domain — cross-cutting, not tied to one command prefix.

The Skydropx brief (section 16) names six sources: `.env`/credentials
files, service-account.json, private keys, SSH keys, Kubernetes Secrets,
Terraform state, Secret Manager, database credentials — and asks for the
same distinction everywhere: metadata access vs. secret value extraction.

Four of those six already have a home:
- Files (`.env`, `service-account.json`, SSH keys, `credentials.json`) —
  `domains/file_guard.py`.
- Kubernetes Secrets (`kubectl get secret` vs `-o yaml`) —
  `domains/kubernetes.py`.
- GCP Secret Manager (`gcloud secrets describe` vs `versions access`) —
  `domains/gcloud.py`.
- Terraform state (`state list` vs `state show`) — `parsers/terraform.py`
  (fixed 2026-09-16 alongside this domain: `state show` was previously
  treated as plain READ despite being able to print secret values).

This module covers the one source that had no home at all: **environment
variables printed directly** (`printenv AWS_SECRET_ACCESS_KEY`,
`env | grep TOKEN`) — this pattern is flagged for strict evaluation
and upgraded here to a real decision instead of a warning nobody has to act on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_SECRET_NAME_RE = re.compile(
    r"\b[A-Za-z0-9_]*("
    r"SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|CREDENTIAL|"
    r"DATABASE_URL|ACCESS_KEY|CLIENT_SECRET|AUTH"
    r")[A-Za-z0-9_]*\b",
    re.IGNORECASE,
)


@dataclass
class EnvVarExposure:
    var_hint: str


def detect_env_var_exposure(command: str) -> EnvVarExposure | None:
    """`printenv NAME` where NAME looks secret-shaped, or `env | grep
    NAME`/`env | rg NAME` doing the same thing via a pipe."""
    m = re.match(r"^\s*printenv\s+([A-Za-z0-9_]+)", command)
    if m and _SECRET_NAME_RE.search(m.group(1)):
        return EnvVarExposure(var_hint=m.group(1))

    if re.search(r"\benv\b\s*\|\s*(grep|rg|egrep)\b", command) and _SECRET_NAME_RE.search(command):
        m2 = _SECRET_NAME_RE.search(command)
        return EnvVarExposure(var_hint=m2.group(0) if m2 else "env")

    return None
