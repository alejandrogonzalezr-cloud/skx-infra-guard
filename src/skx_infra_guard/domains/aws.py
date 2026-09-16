from __future__ import annotations

from skx_infra_guard.core.context import RequestContext
from skx_infra_guard.core.decision import Verdict
from skx_infra_guard.core.policy import PolicyEngine
from skx_infra_guard.core.risk import RiskFactors, combine
from skx_infra_guard.parsers import aws as aws_parser

DOMAIN = "aws"


def evaluate(command: str, ctx: RequestContext, engine: PolicyEngine) -> Verdict | None:
    parsed = aws_parser.parse(command)
    if parsed is None:
        return None

    # IAM/STS mutations are account-wide by nature (same reasoning as GCP's
    # add-iam-policy-binding, docs/skydropx-architecture.md #7.4); anything
    # else operates on one named resource.
    blast_radius = "cluster_or_database" if parsed.touches_iam else "group"
    factors = RiskFactors(
        operation=parsed.operation,
        environment=ctx.environment,
        blast_radius=blast_radius,
        touches_iam=parsed.touches_iam,
    )
    risk = combine(factors)

    verdict = engine.evaluate(
        domain=DOMAIN,
        operation=parsed.operation,
        resource_type=parsed.service,
        risk=risk,
        environment=ctx.environment,
        extra={"verb": parsed.verb or ""},
    )
    verdict.metadata.update({"service": parsed.service, "verb": parsed.verb, "touches_iam": parsed.touches_iam})
    return verdict
