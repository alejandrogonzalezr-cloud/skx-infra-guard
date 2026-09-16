from __future__ import annotations

from skx_infra_guard.core.context import RequestContext
from skx_infra_guard.core.decision import Verdict
from skx_infra_guard.core.policy import PolicyEngine
from skx_infra_guard.core.risk import RiskFactors, combine
from skx_infra_guard.parsers import git as git_parser

DOMAIN = "git"


def evaluate(command: str, ctx: RequestContext, engine: PolicyEngine) -> Verdict | None:
    parsed = git_parser.parse(command)
    if parsed is None:
        return None

    factors = RiskFactors(operation=parsed.operation, environment=ctx.environment)
    risk = combine(factors)

    verdict = engine.evaluate(
        domain=DOMAIN,
        operation=parsed.operation,
        resource_type=parsed.resource_type,
        risk=risk,
        environment=ctx.environment,
    )
    verdict.metadata["subcommand"] = parsed.subcommand
    return verdict
