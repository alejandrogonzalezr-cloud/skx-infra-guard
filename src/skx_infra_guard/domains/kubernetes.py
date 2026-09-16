from __future__ import annotations

from skx_infra_guard.core.context import RequestContext, touches_production_from_elsewhere
from skx_infra_guard.core.decision import OperationClass, Verdict
from skx_infra_guard.core.policy import PolicyEngine
from skx_infra_guard.core.risk import RiskFactors, combine
from skx_infra_guard.parsers import kubernetes as kubectl_parser

DOMAIN = "kubernetes"

# RBAC objects grant/revoke privilege within (or across, for the Cluster*
# variants) the cluster — a `create`/`delete`/`apply` on one of these is an
# IAM change wearing a kubectl costume, not just "editing a resource"
# (Skydropx brief section 17: "Cambios de privilegios deben tener
# políticas específicas"). `get`/`describe` stays a normal read.
_RBAC_RESOURCE_TYPES = {"role", "rolebinding", "clusterrole", "clusterrolebinding"}

# Real Skydropx topology (confirmed 2026-09-15 review): staging is a
# `stg-`-prefixed namespace living in the SAME project/cluster as
# production, not a separate one — so this can't rely on project/account
# env vars alone. The namespace name itself is the resource hint passed to
# the shared core.context.touches_production_from_elsewhere() below.


def evaluate(command: str, ctx: RequestContext, engine: PolicyEngine) -> Verdict | None:
    parsed = kubectl_parser.parse(command)
    if parsed is None:
        return None

    resource_type = parsed.resource_type.rstrip("s").lower() if parsed.resource_type else None
    if parsed.verb == "exec" and ctx.environment.value == "production":
        resource_type = "exec_prod"

    touches_rbac = (
        resource_type in _RBAC_RESOURCE_TYPES
        and parsed.operation in (OperationClass.CHANGE, OperationClass.DESTRUCTIVE)
    )

    factors = RiskFactors(
        operation=parsed.operation,
        environment=ctx.environment,
        blast_radius="cluster_or_database" if touches_rbac else parsed.blast_radius,
        touches_secrets=parsed.exposes_secret_value,
        touches_iam=touches_rbac,
        data_sensitivity="credential" if parsed.exposes_secret_value else "public",
        touches_production_from_elsewhere=touches_production_from_elsewhere(
            parsed.namespace, ctx.environment
        ),
    )
    risk = combine(factors)

    verdict = engine.evaluate(
        domain=DOMAIN,
        operation=parsed.operation,
        resource_type=resource_type,
        risk=risk,
        environment=ctx.environment,
        extra={"verb": parsed.verb},
    )
    verdict.metadata.update(
        {
            "verb": parsed.verb,
            "namespace": parsed.namespace,
            "resource_name": parsed.resource_name,
            "exposes_secret_value": parsed.exposes_secret_value,
        }
    )
    return verdict
