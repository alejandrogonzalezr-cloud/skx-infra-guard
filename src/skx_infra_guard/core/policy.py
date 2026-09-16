"""Policy Engine.

Implements policies-as-code: a base decision matrix (directly from the table
Skydropx specified, policy-model.md #2), escalated by the Risk Engine's output,
and overridable by explicit named rules loaded from versioned YAML files
(policies/global.yaml + policies/<env>.yaml).

Fail-safe: an operation this engine cannot classify is never treated as ALLOW.
Unknown operation defaults to the DESTRUCTIVE row of the base matrix — the
most conservative one.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from skx_infra_guard.core.decision import (
    Decision,
    EnvironmentTier,
    OperationClass,
    RiskLevel,
    Verdict,
)

_BASE_MATRIX: dict[EnvironmentTier, dict[OperationClass, Decision]] = {
    EnvironmentTier.SANDBOX: {
        OperationClass.READ: Decision.ALLOW,
        OperationClass.CHANGE: Decision.ALLOW,
        OperationClass.DESTRUCTIVE: Decision.ASK,
        OperationClass.SECURITY_CRITICAL: Decision.ASK,
    },
    EnvironmentTier.DEV: {
        OperationClass.READ: Decision.ALLOW,
        OperationClass.CHANGE: Decision.ASK,
        OperationClass.DESTRUCTIVE: Decision.ASK,
        OperationClass.SECURITY_CRITICAL: Decision.ASK,
    },
    EnvironmentTier.QA: {
        OperationClass.READ: Decision.ALLOW,
        OperationClass.CHANGE: Decision.ASK,
        OperationClass.DESTRUCTIVE: Decision.BLOCK,
        OperationClass.SECURITY_CRITICAL: Decision.BLOCK,
    },
    EnvironmentTier.STAGING: {
        OperationClass.READ: Decision.ALLOW,
        OperationClass.CHANGE: Decision.ASK,
        OperationClass.DESTRUCTIVE: Decision.BLOCK,
        OperationClass.SECURITY_CRITICAL: Decision.BLOCK,
    },
    EnvironmentTier.PRODUCTION: {
        OperationClass.READ: Decision.ALLOW,
        OperationClass.CHANGE: Decision.ASK,
        OperationClass.DESTRUCTIVE: Decision.BLOCK,
        OperationClass.SECURITY_CRITICAL: Decision.BLOCK,
    },
}

_DECISION_RANK = {Decision.ALLOW: 0, Decision.ASK: 1, Decision.BLOCK: 2}


def _stricter(a: Decision, b: Decision) -> Decision:
    return a if _DECISION_RANK[a] >= _DECISION_RANK[b] else b


@dataclass(frozen=True)
class Rule:
    id: str
    domain: str
    decision: Decision
    reason: str
    operation: OperationClass | None = None
    resource_type: str | None = None
    environments: tuple[EnvironmentTier, ...] | None = None  # None = all envs
    extra_match: tuple[tuple[str, str], ...] = ()  # e.g. (("verb", "delete"),)

    def matches(
        self,
        *,
        domain: str,
        operation: OperationClass,
        resource_type: str | None,
        environment: EnvironmentTier,
        extra: dict[str, str] | None = None,
    ) -> bool:
        if self.domain != domain:
            return False
        if self.operation is not None and self.operation != operation:
            return False
        if self.resource_type is not None and self.resource_type != resource_type:
            return False
        if self.environments is not None and environment not in self.environments:
            return False
        extra = extra or {}
        for key, value in self.extra_match:
            if str(extra.get(key)) != value:
                return False
        return True


_RESERVED_MATCH_KEYS = {"operation", "resource_type"}


def _parse_rule(raw: dict[str, Any]) -> Rule:
    match = raw.get("match", {})
    envs_raw = raw.get("environments")
    envs = tuple(EnvironmentTier(e) for e in envs_raw) if envs_raw else None
    op_raw = match.get("operation")
    extra_match = tuple(
        (k, str(v)) for k, v in match.items() if k not in _RESERVED_MATCH_KEYS
    )
    return Rule(
        id=raw["id"],
        domain=raw["domain"],
        decision=Decision(raw["decision"]),
        reason=raw.get("reason", ""),
        operation=OperationClass(op_raw) if op_raw else None,
        resource_type=match.get("resource_type"),
        environments=envs,
        extra_match=extra_match,
    )


def load_rules(policies_dir: Path, environment: EnvironmentTier) -> list[Rule]:
    """global.yaml rules first (non-overridable), then the environment file."""
    rules: list[Rule] = []
    for filename in ("global.yaml", f"{environment.value}.yaml"):
        path = policies_dir / filename
        if not path.is_file():
            continue
        data = yaml.safe_load(path.read_text()) or {}
        for raw in data.get("rules", []):
            rules.append(_parse_rule(raw))
    return rules


class PolicyEngine:
    def __init__(self, policies_dir: Path):
        self.policies_dir = policies_dir
        self._cache: dict[EnvironmentTier, list[Rule]] = {}

    def _rules_for(self, environment: EnvironmentTier) -> list[Rule]:
        if environment not in self._cache:
            self._cache[environment] = load_rules(self.policies_dir, environment)
        return self._cache[environment]

    def evaluate(
        self,
        *,
        domain: str,
        operation: OperationClass | None,
        resource_type: str | None,
        risk: RiskLevel,
        environment: EnvironmentTier,
        extra: dict[str, str] | None = None,
    ) -> Verdict:
        effective_operation = operation or OperationClass.DESTRUCTIVE  # fail-safe

        for rule in self._rules_for(environment):
            if rule.matches(
                domain=domain,
                operation=effective_operation,
                resource_type=resource_type,
                environment=environment,
                extra=extra,
            ):
                return Verdict(
                    decision=rule.decision,
                    reason=rule.reason,
                    risk=risk,
                    domain=domain,
                    operation=effective_operation,
                    resource=resource_type,
                    rule_id=rule.id,
                    environment=environment,
                )

        base = _BASE_MATRIX[environment][effective_operation]
        if effective_operation == OperationClass.READ:
            # Every environment table in the Skydropx brief says READ is
            # unconditionally ALLOW (sections 4, 6-19) — a sensitive read
            # is worth flagging in the audit log (risk is still reported
            # accurately), but it is never itself a reason to ASK/BLOCK.
            final = base
        else:
            escalated = base
            if risk == RiskLevel.CRITICAL:
                escalated = Decision.BLOCK
            elif risk == RiskLevel.HIGH and base == Decision.ALLOW:
                escalated = Decision.ASK
            final = _stricter(base, escalated)

        return Verdict(
            decision=final,
            reason=(
                f"default policy for {domain}/{effective_operation.value} "
                f"in {environment.value} (risk={risk.value})"
            ),
            risk=risk,
            domain=domain,
            operation=effective_operation,
            resource=resource_type,
            rule_id=None,
            environment=environment,
        )
