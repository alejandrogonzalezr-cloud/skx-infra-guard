from __future__ import annotations

from skx_infra_guard.core.context import RequestContext
from skx_infra_guard.core.decision import Verdict
from skx_infra_guard.core.policy import PolicyEngine
from skx_infra_guard.core.risk import RiskFactors, combine
from skx_infra_guard.parsers import mongodb as mongo_parser

DOMAIN = "mongodb"


def evaluate(command: str, ctx: RequestContext, engine: PolicyEngine) -> Verdict | None:
    parsed = mongo_parser.parse(command)
    if parsed is None:
        return None

    blast_radius = "cluster_or_database" if parsed.always_blocked else "group"
    factors = RiskFactors(operation=parsed.operation, environment=ctx.environment, blast_radius=blast_radius)
    risk = combine(factors)

    resource_type = parsed.methods_found[-1].lower() if parsed.methods_found else "unknown"

    verdict = engine.evaluate(
        domain=DOMAIN,
        operation=parsed.operation,
        resource_type=resource_type,
        risk=risk,
        environment=ctx.environment,
    )
    if parsed.always_blocked and parsed.always_blocked_reason:
        verdict.reason = parsed.always_blocked_reason
    verdict.metadata.update({"methods_found": parsed.methods_found, "always_blocked": parsed.always_blocked})
    return verdict
