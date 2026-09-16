"""Risk Engine.

Implements a robust cross-domain engine driven by explicit, named factors
to calculate operational and security risk levels (CRITICAL/HIGH/ELEVATED/MEDIUM/SAFE).

Each factor is a small pure function. combine() folds them by taking the
highest risk any single factor reports, then applies a couple of documented
escalation rules (production always raises the floor; sandbox operating on
a non-sandbox resource is treated as its target's tier, see
docs/threat-model.md #10).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from skx_infra_guard.core.decision import EnvironmentTier, OperationClass, RiskLevel

DataSensitivity = str  # "public" | "internal" | "sensitive" | "pii" | "financial" | "credential" | "critical"

_SENSITIVITY_RANK: dict[str, int] = {
    "public": 0,
    "internal": 1,
    "sensitive": 2,
    "pii": 3,
    "financial": 3,
    "credential": 3,
    "critical": 3,
}

BlastRadius = str  # "single" | "group" | "namespace_or_schema" | "cluster_or_database"

_BLAST_RANK: dict[str, int] = {
    "single": 0,
    "group": 1,
    "namespace_or_schema": 2,
    "cluster_or_database": 3,
}


@dataclass
class RiskFactors:
    operation: OperationClass
    environment: EnvironmentTier
    blast_radius: BlastRadius = "single"
    # Default is "public" (no bump) rather than "internal": sensitivity is
    # a data-domain concept (docs/policy-model.md #9). Non-data domains
    # (kubernetes, terraform, git) never set this, so it must not silently
    # inject risk into commands that have nothing to do with data exposure.
    # domains/database.py explicitly overrides it to "internal"/"sensitive".
    data_sensitivity: DataSensitivity = "public"
    touches_production_from_elsewhere: bool = False
    touches_iam: bool = False
    touches_secrets: bool = False
    extra_notes: list[str] = field(default_factory=list)


def _operation_floor(op: OperationClass) -> RiskLevel:
    return {
        OperationClass.READ: RiskLevel.LOW,
        OperationClass.CHANGE: RiskLevel.MEDIUM,
        OperationClass.DESTRUCTIVE: RiskLevel.HIGH,
        OperationClass.SECURITY_CRITICAL: RiskLevel.HIGH,
    }[op]


def _environment_bump(op: OperationClass, env: EnvironmentTier) -> RiskLevel:
    """Production/staging raise the floor for change+destructive ops, matching
    the dev/staging/production behavior matrix extended to 5 tiers."""
    if op == OperationClass.READ:
        return RiskLevel.LOW
    if env == EnvironmentTier.PRODUCTION:
        return RiskLevel.CRITICAL if op == OperationClass.DESTRUCTIVE else RiskLevel.HIGH
    if env == EnvironmentTier.STAGING:
        return RiskLevel.HIGH if op == OperationClass.DESTRUCTIVE else RiskLevel.MEDIUM
    if env == EnvironmentTier.QA:
        return RiskLevel.HIGH if op == OperationClass.DESTRUCTIVE else RiskLevel.MEDIUM
    if env == EnvironmentTier.DEV:
        return RiskLevel.MEDIUM if op == OperationClass.DESTRUCTIVE else RiskLevel.LOW
    # sandbox
    return RiskLevel.MEDIUM if op == OperationClass.DESTRUCTIVE else RiskLevel.LOW


def _blast_radius_bump(radius: BlastRadius) -> RiskLevel:
    rank = _BLAST_RANK.get(radius, 0)
    return [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL][rank]


def _sensitivity_bump(sensitivity: DataSensitivity) -> RiskLevel:
    rank = _SENSITIVITY_RANK.get(sensitivity, 1)
    return [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL][rank]


def combine(factors: RiskFactors) -> RiskLevel:
    candidates = [
        _operation_floor(factors.operation),
        _environment_bump(factors.operation, factors.environment),
        _sensitivity_bump(factors.data_sensitivity),
    ]

    if factors.operation != OperationClass.READ:
        # Blast radius describes the impact of a change/destroy — it isn't
        # meaningful for a read (listing every pod in a namespace isn't
        # "riskier" in the destructive sense than listing one, even though
        # it may be worth flagging for data-sensitivity reasons instead,
        # which _sensitivity_bump already covers above).
        candidates.append(_blast_radius_bump(factors.blast_radius))

    if factors.touches_iam or factors.touches_secrets:
        candidates.append(RiskLevel.HIGH)

    if factors.touches_production_from_elsewhere:
        # Sandbox/dev reaching into a production resource must never be
        # treated as merely "elevated" — the brief's own wording is
        # "escalate risk OR block" (docs/threat-model.md #10), and CRITICAL
        # is what actually forces policy.py's escalation to BLOCK
        # unconditionally rather than just nudging ALLOW to ASK.
        candidates.append(RiskLevel.CRITICAL)

    return max(candidates, key=lambda r: r.rank)
