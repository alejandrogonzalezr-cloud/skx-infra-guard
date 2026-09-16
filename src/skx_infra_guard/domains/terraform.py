from __future__ import annotations

from skx_infra_guard.core.context import RequestContext
from skx_infra_guard.core.decision import Verdict
from skx_infra_guard.core.policy import PolicyEngine
from skx_infra_guard.core.risk import RiskFactors, combine
from skx_infra_guard.parsers import terraform as tf_parser

DOMAIN = "terraform"


def evaluate(command: str, ctx: RequestContext, engine: PolicyEngine) -> Verdict | None:
    parsed = tf_parser.parse(command)
    if parsed is None:
        return None

    factors = RiskFactors(
        operation=parsed.operation,
        environment=ctx.environment,
        touches_secrets=parsed.exposes_secret_value,
        data_sensitivity="credential" if parsed.exposes_secret_value else "public",
    )
    risk = combine(factors)

    verdict = engine.evaluate(
        domain=DOMAIN,
        operation=parsed.operation,
        resource_type=parsed.subcommand,
        risk=risk,
        environment=ctx.environment,
    )
    verdict.metadata["subcommand"] = parsed.subcommand
    verdict.metadata["exposes_secret_value"] = parsed.exposes_secret_value
    return verdict


def evaluate_plan_output(output: str, ctx: RequestContext, engine: PolicyEngine) -> Verdict | None:
    """Used by the PostToolUse path (the successor to cicd-integration.sh's
    terraform-plan detection) to analyze what a completed `plan`/`apply`
    actually changed, not just that a plan happened.
    See docs/threat-model.md #13 for the gap this closes.
    """
    from skx_infra_guard.core.decision import OperationClass

    summary = tf_parser.analyze_plan_output(output)
    if summary is None or summary.no_changes:
        return None

    factors = RiskFactors(
        operation=OperationClass.DESTRUCTIVE if summary.to_destroy else OperationClass.CHANGE,
        environment=ctx.environment,
        blast_radius=summary.blast_radius,
        touches_iam=summary.destroys_sensitive_resource,
    )
    risk = combine(factors)

    verdict = engine.evaluate(
        domain=DOMAIN,
        operation=factors.operation,
        resource_type="plan_content",
        risk=risk,
        environment=ctx.environment,
    )
    verdict.metadata.update(
        {
            "to_add": summary.to_add,
            "to_change": summary.to_change,
            "to_destroy": summary.to_destroy,
            "destroyed_addresses": summary.destroyed_addresses,
        }
    )
    return verdict
