"""Audit Engine.

Implements structured logging (JSONL + flock) with the extra fields the
User Policy / Agent Policy split and multi-domain design need. The
append-under-flock mechanism ensures concurrency safety across multiple
active agent sessions.
"""

from __future__ import annotations

import fcntl
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from skx_infra_guard.core.decision import Verdict

DEFAULT_LOG_DIR = Path(os.environ.get("SKX_LOG_DIR", os.environ.get("LOG_DIR", "~/.claude/logs"))).expanduser()


@dataclass
class AuditEvent:
    timestamp: str
    event: str
    tool: str
    status: str
    detail: str
    environment: str
    session: str
    domain: str = ""
    actor: str = ""
    rule_id: str | None = None
    risk: str = ""


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class AuditEngine:
    def __init__(self, log_dir: Path | None = None):
        self.log_dir = log_dir or DEFAULT_LOG_DIR
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.audit_log = self.log_dir / "audit.jsonl"

    def log(self, event: AuditEvent) -> None:
        line = json.dumps(asdict(event))
        lock_path = self.audit_log.with_suffix(self.audit_log.suffix + ".lock")
        with open(lock_path, "w") as lockfile:
            fcntl.flock(lockfile, fcntl.LOCK_EX)
            try:
                with open(self.audit_log, "a") as f:
                    f.write(line + "\n")
            finally:
                fcntl.flock(lockfile, fcntl.LOCK_UN)

    def log_verdict(
        self,
        verdict: Verdict,
        *,
        tool: str,
        session_id: str,
        actor: str = "agent",
    ) -> None:
        self.log(
            AuditEvent(
                timestamp=now_iso(),
                event=verdict.decision.value,
                tool=tool,
                status=verdict.decision.value,
                detail=verdict.reason,
                environment=verdict.environment.value if verdict.environment else "unknown",
                session=session_id,
                domain=verdict.domain,
                actor=actor,
                rule_id=verdict.rule_id,
                risk=verdict.risk.value,
            )
        )
