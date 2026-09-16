"""Core decision types shared by every domain and by the Policy Engine.

The Claude Code hook protocol itself is binary (allow/deny — confirmed against
the official hooks docs, see docs/skydropx-architecture.md #7.2). ASK is a
decision our own Policy Engine can reach; turning ASK into an actual
allow/deny for Claude Code happens one layer up, in the Approval Engine
(see approval/sentinel.py) and the CLI dispatcher (cli.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Decision(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    BLOCK = "block"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]

    def __lt__(self, other: "RiskLevel") -> bool:
        return self.rank < other.rank

    def __ge__(self, other: "RiskLevel") -> bool:
        return self.rank >= other.rank


class OperationClass(str, Enum):
    READ = "read"
    CHANGE = "change"
    DESTRUCTIVE = "destructive"
    SECURITY_CRITICAL = "security_critical"


class EnvironmentTier(str, Enum):
    SANDBOX = "sandbox"
    DEV = "dev"
    QA = "qa"
    STAGING = "staging"
    PRODUCTION = "production"

    @property
    def rank(self) -> int:
        return {"sandbox": 0, "dev": 1, "qa": 2, "staging": 3, "production": 4}[self.value]


@dataclass
class Verdict:
    """The result of evaluating one effective command against one domain."""

    decision: Decision
    reason: str
    risk: RiskLevel
    domain: str
    operation: OperationClass | None = None
    resource: str | None = None
    rule_id: str | None = None
    environment: EnvironmentTier | None = None
    metadata: dict = field(default_factory=dict)

    def is_terminal_block(self) -> bool:
        return self.decision == Decision.BLOCK


ALLOW_PASSTHROUGH = Verdict(
    decision=Decision.ALLOW,
    reason="no applicable rule",
    risk=RiskLevel.LOW,
    domain="none",
)
