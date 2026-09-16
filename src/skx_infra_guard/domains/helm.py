from __future__ import annotations

from skx_infra_guard.core.context import RequestContext
from skx_infra_guard.core.decision import Verdict
from skx_infra_guard.core.policy import PolicyEngine
from skx_infra_guard.core.risk import RiskFactors, combine
from skx_infra_guard.parsers import helm as helm_parser

DOMAIN = "helm"


def evaluate(command: str, ctx: RequestContext, engine: PolicyEngine) -> Verdict | None:
    parsed = helm_parser.parse(command)
    if parsed is None:
        return None

    # A release is one deployable unit — "group"-scale, not project-wide,
    # unless it's being uninstalled entirely (still just that one release,
    # so this stays "group" rather than escalating further; a release can
    # itself contain many K8s objects, but Helm operates on it as a unit).
    factors = RiskFactors(operation=parsed.operation, environment=ctx.environment, blast_radius="group")
    risk = combine(factors)

    verdict = engine.evaluate(
        domain=DOMAIN,
        operation=parsed.operation,
        resource_type=parsed.subcommand,
        risk=risk,
        environment=ctx.environment,
    )
    verdict.metadata.update({"subcommand": parsed.subcommand, "release_name": parsed.release_name})
    return verdict
