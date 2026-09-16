from skx_infra_guard.core.decision import EnvironmentTier, OperationClass, RiskLevel
from skx_infra_guard.core.risk import RiskFactors, combine


def test_read_is_always_low_regardless_of_environment():
    for env in EnvironmentTier:
        risk = combine(RiskFactors(operation=OperationClass.READ, environment=env))
        assert risk == RiskLevel.LOW, env


def test_read_can_still_be_flagged_by_sensitivity_without_blast_radius():
    risk = combine(
        RiskFactors(
            operation=OperationClass.READ,
            environment=EnvironmentTier.PRODUCTION,
            blast_radius="cluster_or_database",  # should be ignored for reads
            data_sensitivity="sensitive",
        )
    )
    assert risk == RiskLevel.HIGH  # from sensitivity, not blast radius


def test_destructive_in_production_is_critical():
    risk = combine(
        RiskFactors(operation=OperationClass.DESTRUCTIVE, environment=EnvironmentTier.PRODUCTION)
    )
    assert risk == RiskLevel.CRITICAL


def test_destructive_in_sandbox_is_lower_than_in_production():
    sandbox_risk = combine(
        RiskFactors(operation=OperationClass.DESTRUCTIVE, environment=EnvironmentTier.SANDBOX)
    )
    prod_risk = combine(
        RiskFactors(operation=OperationClass.DESTRUCTIVE, environment=EnvironmentTier.PRODUCTION)
    )
    assert sandbox_risk.rank < prod_risk.rank


def test_credential_sensitivity_does_not_crash_the_rank_lookup():
    # Found 2026-09-16 while building the Secrets domain: "credential" and
    # "critical" mapped to rank 4 in a 4-element (0-3) lookup table, so any
    # command that exposed a real secret value crashed with IndexError
    # instead of producing a verdict — latent since nothing had exercised
    # combine() with data_sensitivity="credential" until this domain.
    for sensitivity in ("credential", "critical", "pii", "financial"):
        risk = combine(
            RiskFactors(
                operation=OperationClass.SECURITY_CRITICAL,
                environment=EnvironmentTier.PRODUCTION,
                data_sensitivity=sensitivity,
            )
        )
        assert risk == RiskLevel.CRITICAL


def test_touches_production_from_elsewhere_forces_at_least_high():
    risk = combine(
        RiskFactors(
            operation=OperationClass.READ,
            environment=EnvironmentTier.SANDBOX,
            touches_production_from_elsewhere=True,
        )
    )
    # READ's blast-radius exemption doesn't apply to this escalation path —
    # touching prod from sandbox is a distinct, explicit factor.
    assert risk.rank >= RiskLevel.HIGH.rank
