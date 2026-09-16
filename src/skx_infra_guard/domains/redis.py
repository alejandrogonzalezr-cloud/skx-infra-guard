from __future__ import annotations

from skx_infra_guard.core.context import RequestContext
from skx_infra_guard.core.decision import Verdict
from skx_infra_guard.core.policy import PolicyEngine
from skx_infra_guard.core.risk import RiskFactors, combine
from skx_infra_guard.parsers import redis as redis_parser

DOMAIN = "redis"


def evaluate(command: str, ctx: RequestContext, engine: PolicyEngine) -> Verdict | None:
    parsed = redis_parser.parse(command)
    if parsed is None:
        return None

    # FLUSHALL/FLUSHDB wipe the entire instance — that's the one Redis
    # operation that's genuinely instance-wide, everything else touches at
    # most the keys named on the command line.
    blast_radius = "cluster_or_database" if parsed.always_blocked else "single"

    factors = RiskFactors(operation=parsed.operation, environment=ctx.environment, blast_radius=blast_radius)
    risk = combine(factors)

    verdict = engine.evaluate(
        domain=DOMAIN,
        operation=parsed.operation,
        resource_type=parsed.command,
        risk=risk,
        environment=ctx.environment,
    )
    verdict.metadata.update({"command": parsed.command, "key_hint": parsed.key_hint})
    return verdict
