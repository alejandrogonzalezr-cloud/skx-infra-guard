"""General shell command safety net.

Enforces HIGH-severity safety patterns and sensitive-file-read patterns, run on 
every effective command produced by the Command Normalizer (so `bash -c "rm -rf /"` 
is caught the same way plain `rm -rf /` is — see docs/threat-model.md #9).

These checks are not environment-gated (a fork bomb is a fork bomb in every
environment), so they're wired as `global`-tier BLOCKs directly here rather
than through policies/global.yaml — there's no meaningful "match on
resource_type" shape for "this whole class of command is always dangerous".
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from skx_infra_guard.core.decision import Decision, EnvironmentTier, RiskLevel, Verdict

DOMAIN = "shell"

_HIGH_SEVERITY_PATTERNS: list[tuple[str, str, str]] = [
    # (id, regex, human reason)
    ("rm_rf_root", r"rm\s+.*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s*(--\s*)?(/\s|/$|~/|\.\./)", "rm -rf on root/home/parent directory"),
    ("rm_rf_home", r"rm\s+.*-rf\s*\$HOME", "rm -rf on $HOME"),
    ("fork_bomb", r":\(\)\s*\{\s*:\|:", "fork bomb pattern"),
    ("disk_wipe", r"dd\s+.*of=/dev/(sd[a-z]|nvme\d|disk\d|vd[a-z]|xvd[a-z])", "dd write to a block device"),
    ("pipe_to_shell", r"(curl|wget)\s+.*\|\s*(bash|sh|zsh|fish|python|ruby|perl|node)\b", "pipe-to-shell (remote code execution)"),
    ("base64_pipe_shell", r"base64\s+.*(--decode|-d)\b.*\|\s*(bash|sh|zsh|python|ruby|perl)\b", "base64-decode piped to a shell"),
    ("firewall_flush", r"iptables\s+-F\b", "iptables -F (flush all rules)"),
    ("sudo_tee_system", r"(sudo|su)\s+.*tee\s+.*/(etc|usr)\b", "sudo tee write to /etc or /usr"),
    ("pipe_to_crontab", r"\|\s*crontab\s*$", "pipe to crontab (persistence mechanism)"),
    ("chmod_777_system", r"chmod\s+.*-R\s+.*777\s*(--\s*)?(/\s|~/|/home|/root|/etc)", "chmod -R 777 on a system path"),
    ("history_clear", r"history\s+-c\b", "clearing shell history (audit tampering)"),
    ("bash_history_overwrite", r">\s*(~/\.bash_history|\$HOME/\.bash_history)", "overwriting ~/.bash_history"),
    ("system_file_write", r"(tee\s+|>\s*)/etc/(passwd|shadow|sudoers|gshadow|master\.passwd)\b", "write to /etc/passwd|shadow|sudoers"),
    ("kernel_module", r"^\s*(insmod|rmmod|modprobe)\s", "kernel module operation"),
    ("log_tamper_redirect", r">\s*/var/log/", "redirect into /var/log/ (log tampering)"),
    ("log_tamper_shred", r"shred\s+.*(/var/log/|/var/audit/)", "shredding log files"),
    ("cloud_metadata_ssrf", r"169\.254\.169\.254", "cloud metadata endpoint access"),
    ("privilege_escalation", r"^\s*(sudo\s+-i|sudo\s+-s|su\s+-|sudo\s+su)\b", "interactive root shell escalation"),
    ("ssh_authorized_keys", r">>\s*.*\.ssh/authorized_keys", "appending to ~/.ssh/authorized_keys (backdoor)"),
    ("etc_hosts_write", r"(>>|tee)\s*/etc/hosts", "writing to /etc/hosts (DNS hijack)"),
]

_SENSITIVE_FILE_PATTERNS = [
    r"\.env\.?(local|production|staging|test)?\b",
    r"/etc/shadow\b",
    r"/etc/gshadow\b",
    r"/etc/master\.passwd\b",
    r"\.ssh/id_(rsa|ed25519|ecdsa|dsa)\b",
    r"\.ssh/authorized_keys\b",
    r"\.aws/credentials\b",
    r"\.kube/config\b",
    r"\.docker/config\.json\b",
    r"\.npmrc\b",
    r"\.pypirc\b",
    r"\.netrc\b",
    r"\.git-credentials\b",
    r"/proc/self/environ\b",
    r"/proc/\d+/environ\b",
    r"\.(pem|p12|pfx|key)\b",
    r"secrets\.json\b",
    r"credentials\.json\b",
]
_READ_COMMAND_PREFIX = re.compile(r"^\s*(cat|bat|less|more|head|tail|print|strings)\s")


@dataclass
class ShellSafetyHit:
    rule_id: str
    reason: str


def check(command: str) -> ShellSafetyHit | None:
    for rule_id, pattern, reason in _HIGH_SEVERITY_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return ShellSafetyHit(rule_id=f"shell.{rule_id}", reason=reason)

    if _READ_COMMAND_PREFIX.match(command):
        for pattern in _SENSITIVE_FILE_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return ShellSafetyHit(
                    rule_id="shell.sensitive_file_read",
                    reason="attempt to read a sensitive credential file",
                )
    return None


def evaluate(command: str, environment: EnvironmentTier) -> Verdict | None:
    hit = check(command)
    if hit is None:
        return None
    return Verdict(
        decision=Decision.BLOCK,
        reason=hit.reason,
        risk=RiskLevel.CRITICAL,
        domain=DOMAIN,
        rule_id=hit.rule_id,
        environment=environment,
    )
