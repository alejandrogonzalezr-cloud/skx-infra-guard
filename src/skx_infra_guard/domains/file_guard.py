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

_SYSTEM_PATH_WRITE_PATTERNS = [
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
]

# Canonical credential/secret file pattern BODIES (no anchor), shared by
# write-protection (below), sensitive-read detection (SENSITIVE_READ_PATTERNS
# below), and domains/shell_safety.py's own cat/head/etc. sensitive-read
# check, which imports this instead of keeping its own copy. Previously each
# of the three lists was maintained independently and had already drifted —
# the read list was missing .tfstate, .ssh/known_hosts, .ssh/config, and the
# .ssh/*.pub|.pem|.key wildcard that the write list already had (found in
# the 2026-09 review). One body list now, so a fix here can't fail to reach
# the others. Left unanchored here because the two callers need different
# anchors: file_guard matches an isolated path (anchor at the end, `$`),
# shell_safety matches a path substring inside a whole command line (anchor
# at a word boundary, `\b`).
CREDENTIAL_FILE_PATTERN_BODIES = [
    r"\.ssh/(authorized_keys|id_rsa|id_ed25519|id_ecdsa|id_dsa|known_hosts|config)",
    r"\.ssh/.*\.(pub|pem|key)",
    r"\.aws/credentials",
    r"\.aws/config",
    r"\.kube/config",
    r"\.docker/config\.json",
    r"\.npmrc",
    r"\.pypirc",
    r"\.netrc",
    r"\.git-credentials",
    r"secrets\.(json|yaml|yml|env)",
    r"credentials\.(json|yaml|yml)",
    r"\.(pem|p12|pfx|key)",
    r"\.tfstate(\.backup)?",  # ported from infra-guard.sh — state must only
    # be touched by terraform itself
]

CREDENTIAL_FILE_PATTERNS = [body + r"$" for body in CREDENTIAL_FILE_PATTERN_BODIES]

_PROTECTED_WRITE_PATTERNS = _SYSTEM_PATH_WRITE_PATTERNS + CREDENTIAL_FILE_PATTERNS

# Read-only extras: meaningless as WRITE protections (nothing "writes" its
# own /proc/self/environ or /etc/shadow through this path), but reading them
# exposes secrets the same way the credential files above do.
_READ_ONLY_EXTRA_PATTERNS = [
    r"\.env(\.local|\.production|\.staging|\.test)?$",
    r"/etc/shadow$",
    r"/etc/gshadow$",
    r"/etc/master\.passwd$",
    r"/proc/self/environ$",
    r"/proc/\d+/environ$",
]

SENSITIVE_READ_PATTERNS = CREDENTIAL_FILE_PATTERNS + _READ_ONLY_EXTRA_PATTERNS


def _resolve(path: str, cwd: str | None) -> str:
    """Expand `~` and resolve against the tool call's cwd before matching.
    Without this, a relative path like `../../../../etc/passwd` never starts
    with the literal string `/etc/` and slides past every anchored pattern
    below untouched (found in the 2026-09 review). `normpath` — not
    `realpath` — is enough to collapse `../` lexically without requiring the
    path to actually exist.
    """
    expanded = os.path.expanduser(path)
    if cwd and not os.path.isabs(expanded):
        expanded = os.path.join(cwd, expanded)
    return os.path.normpath(expanded)


def check_write(path: str, cwd: str | None = None) -> str | None:
    resolved = _resolve(path, cwd)
    for pattern in _PROTECTED_WRITE_PATTERNS:
        if re.search(pattern, resolved, re.IGNORECASE):
            return pattern
    return None


def check_read(path: str, cwd: str | None = None) -> str | None:
    resolved = _resolve(path, cwd)
    for pattern in SENSITIVE_READ_PATTERNS:
        if re.search(pattern, resolved, re.IGNORECASE):
            return pattern
    return None


def evaluate_write(paths: list[str], environment: EnvironmentTier, cwd: str | None = None) -> Verdict | None:
    for path in paths:
        pattern = check_write(path, cwd)
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


def evaluate_read(paths: list[str], environment: EnvironmentTier, cwd: str | None = None) -> Verdict | None:
    for path in paths:
        pattern = check_read(path, cwd)
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
