"""The sandbox/dev-reaching-into-production escalation
(docs/threat-model.md #10, core.context.touches_production_from_elsewhere)
was only wired into domains/kubernetes.py — an equivalent RDS/Cloud
SQL/database operation against a production-named resource got none of the
CRITICAL-risk escalation a kubectl namespace argument would trigger (found
in the 2026-09 review). These mirror
tests/unit/test_kubernetes_domain_cross_environment.py for the other
domains it's now wired into.
"""

from pathlib import Path

from skx_infra_guard.core.context import RequestContext
from skx_infra_guard.core.decision import EnvironmentTier, RiskLevel
from skx_infra_guard.core.policy import PolicyEngine
from skx_infra_guard.domains import aws, database, gcloud

POLICIES_DIR = Path(__file__).resolve().parents[2] / "policies"


def _evaluate(domain_module, command: str, environment: EnvironmentTier):
    ctx = RequestContext(tool_name="Bash", environment=environment)
    return domain_module.evaluate(command, ctx, PolicyEngine(POLICIES_DIR))


def test_aws_rds_delete_from_sandbox_against_prod_named_instance_is_critical():
    verdict = _evaluate(
        aws,
        "aws rds delete-db-instance --db-instance-identifier prod-orders-db --skip-final-snapshot",
        EnvironmentTier.SANDBOX,
    )
    assert verdict is not None
    assert verdict.risk == RiskLevel.CRITICAL


def test_aws_rds_delete_against_its_own_sandbox_named_instance_is_not_escalated():
    verdict = _evaluate(
        aws,
        "aws rds delete-db-instance --db-instance-identifier sandbox-scratch-db --skip-final-snapshot",
        EnvironmentTier.SANDBOX,
    )
    assert verdict.risk != RiskLevel.CRITICAL


def test_aws_describe_instances_mentioning_production_is_not_escalated():
    # A read must never be escalated just because "production" appears in a
    # filter value — only non-READ operations trigger this check.
    verdict = _evaluate(
        aws,
        "aws ec2 describe-instances --filters Name=tag:Env,Values=production",
        EnvironmentTier.SANDBOX,
    )
    assert verdict.risk != RiskLevel.CRITICAL


def test_gcloud_sql_delete_from_sandbox_against_prod_named_instance_is_critical():
    verdict = _evaluate(gcloud, "gcloud sql instances delete prod-billing", EnvironmentTier.SANDBOX)
    assert verdict is not None
    assert verdict.risk == RiskLevel.CRITICAL


def test_psql_drop_table_from_sandbox_against_prod_host_is_critical():
    verdict = _evaluate(
        database,
        "psql -h prod-db.internal -c 'DROP TABLE users;'",
        EnvironmentTier.SANDBOX,
    )
    assert verdict is not None
    assert verdict.risk == RiskLevel.CRITICAL


def test_psql_select_against_prod_host_is_not_escalated_because_it_is_a_read():
    verdict = _evaluate(
        database,
        "psql -h prod-db.internal -c 'SELECT * FROM users WHERE id=1'",
        EnvironmentTier.SANDBOX,
    )
    assert verdict.risk != RiskLevel.CRITICAL
