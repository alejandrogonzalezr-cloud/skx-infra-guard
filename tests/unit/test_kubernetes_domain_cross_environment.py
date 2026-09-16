"""Tests for the sandbox/dev-reaching-into-production escalation
(docs/threat-model.md #10), fixed 2026-09-15 after the expert review found
`touches_production_from_elsewhere` was defined but never actually set by
any domain."""

from pathlib import Path

from skx_infra_guard.core.context import RequestContext
from skx_infra_guard.core.decision import Decision, EnvironmentTier, RiskLevel
from skx_infra_guard.core.policy import PolicyEngine
from skx_infra_guard.domains import kubernetes

POLICIES_DIR = Path(__file__).resolve().parents[2] / "policies"


def _evaluate(command: str, environment: EnvironmentTier):
    ctx = RequestContext(tool_name="Bash", environment=environment)
    return kubernetes.evaluate(command, ctx, PolicyEngine(POLICIES_DIR))


def test_sandbox_change_against_a_production_looking_namespace_is_critical_risk():
    verdict = _evaluate("kubectl apply -f x.yaml -n production", EnvironmentTier.SANDBOX)
    assert verdict.risk == RiskLevel.CRITICAL


def test_sandbox_change_against_its_own_namespace_is_not_escalated():
    verdict = _evaluate("kubectl apply -f x.yaml -n stg-labels-light", EnvironmentTier.SANDBOX)
    assert verdict.risk != RiskLevel.CRITICAL


def test_sandbox_destructive_against_production_namespace_is_blocked_not_just_asked():
    # DESTRUCTIVE + CRITICAL risk must force BLOCK even though sandbox's own
    # base matrix row for DESTRUCTIVE is only ASK.
    verdict = _evaluate("kubectl scale deployment/api --replicas=0 -n production", EnvironmentTier.SANDBOX)
    assert verdict.operation.value == "change"  # scale is CHANGE, not destructive — still escalates
    assert verdict.decision in (Decision.ASK, Decision.BLOCK)
    assert verdict.risk == RiskLevel.CRITICAL


def test_already_production_ambient_does_not_double_flag():
    verdict = _evaluate("kubectl get pods -n production", EnvironmentTier.PRODUCTION)
    # Ambient is already production, so this isn't an "elsewhere reaching
    # in" case — ordinary production risk rules apply instead.
    assert verdict.risk != RiskLevel.CRITICAL or verdict.operation.value == "read"
