from __future__ import annotations

from skx_infra_guard.core.context import RequestContext
from skx_infra_guard.core.decision import OperationClass, Verdict
from skx_infra_guard.core.policy import PolicyEngine
from skx_infra_guard.core.risk import RiskFactors, combine
from skx_infra_guard.parsers import secrets as secrets_parser

DOMAIN = "secrets"


def evaluate(command: str, ctx: RequestContext, engine: PolicyEngine) -> Verdict | None:
    exposure = secrets_parser.detect_env_var_exposure(command)
    if exposure is None:
        return None

    factors = RiskFactors(
        operation=OperationClass.SECURITY_CRITICAL,
        environment=ctx.environment,
        touches_secrets=True,
        data_sensitivity="credential",
    )
    risk = combine(factors)

    verdict = engine.evaluate(
        domain=DOMAIN,
        operation=OperationClass.SECURITY_CRITICAL,
        resource_type="env_var",
        risk=risk,
        environment=ctx.environment,
    )
    verdict.reason = verdict.reason or f"prints the value of an environment variable that looks like a secret ({exposure.var_hint})"
    verdict.metadata["var_hint"] = exposure.var_hint
    return verdict
