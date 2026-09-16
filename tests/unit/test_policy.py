from pathlib import Path

import pytest

from skx_infra_guard.core.decision import Decision, EnvironmentTier, OperationClass, RiskLevel
from skx_infra_guard.core.policy import PolicyEngine

POLICIES_DIR = Path(__file__).resolve().parents[2] / "policies"


@pytest.fixture
def engine():
    return PolicyEngine(POLICIES_DIR)


def test_read_is_always_allow_in_every_environment(engine):
    for env in EnvironmentTier:
        verdict = engine.evaluate(
            domain="kubernetes",
            operation=OperationClass.READ,
            resource_type="pod",
            risk=RiskLevel.CRITICAL,  # even if something inflated risk, READ stays ALLOW
            environment=env,
        )
        assert verdict.decision == Decision.ALLOW, env


def test_kubectl_delete_always_blocked_regardless_of_environment(engine):
    for env in EnvironmentTier:
        verdict = engine.evaluate(
            domain="kubernetes",
            operation=OperationClass.DESTRUCTIVE,
            resource_type="namespace",
            risk=RiskLevel.CRITICAL,
            environment=env,
            extra={"verb": "delete"},
        )
        assert verdict.decision == Decision.BLOCK, env
        assert verdict.rule_id == "global.k8s.delete"


def test_terraform_destroy_always_blocked(engine):
    verdict = engine.evaluate(
        domain="terraform",
        operation=OperationClass.DESTRUCTIVE,
        resource_type="destroy",
        risk=RiskLevel.CRITICAL,
        environment=EnvironmentTier.SANDBOX,
    )
    assert verdict.decision == Decision.BLOCK
    assert verdict.rule_id == "global.terraform.destroy"


def test_git_force_push_always_blocked(engine):
    verdict = engine.evaluate(
        domain="git",
        operation=OperationClass.DESTRUCTIVE,
        resource_type="force_push",
        risk=RiskLevel.HIGH,
        environment=EnvironmentTier.DEV,
    )
    assert verdict.decision == Decision.BLOCK
    assert verdict.rule_id == "global.git.force_push"


def test_sandbox_change_is_allowed_by_default_matrix(engine):
    verdict = engine.evaluate(
        domain="kubernetes",
        operation=OperationClass.CHANGE,
        resource_type="deployment",
        risk=RiskLevel.LOW,
        environment=EnvironmentTier.SANDBOX,
    )
    assert verdict.decision == Decision.ALLOW


def test_production_change_is_ask_by_default_matrix(engine):
    verdict = engine.evaluate(
        domain="kubernetes",
        operation=OperationClass.CHANGE,
        resource_type="deployment",
        risk=RiskLevel.MEDIUM,
        environment=EnvironmentTier.PRODUCTION,
    )
    assert verdict.decision == Decision.ASK


def test_unknown_operation_fails_safe_to_destructive_row(engine):
    verdict = engine.evaluate(
        domain="kubernetes",
        operation=None,
        resource_type="whatever",
        risk=RiskLevel.LOW,
        environment=EnvironmentTier.PRODUCTION,
    )
    # Fail-safe: unknown operation -> treated as destructive -> blocked in prod
    assert verdict.decision == Decision.BLOCK
    assert verdict.operation == OperationClass.DESTRUCTIVE


def test_critical_risk_forces_block_even_off_a_permissive_base(engine):
    verdict = engine.evaluate(
        domain="terraform",
        operation=OperationClass.CHANGE,
        resource_type="apply",
        risk=RiskLevel.CRITICAL,
        environment=EnvironmentTier.SANDBOX,  # base matrix would say ALLOW for CHANGE
    )
    assert verdict.decision == Decision.BLOCK
