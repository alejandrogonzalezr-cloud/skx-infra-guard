from __future__ import annotations

from skx_infra_guard.core.context import RequestContext
from skx_infra_guard.core.decision import Verdict
from skx_infra_guard.core.policy import PolicyEngine
from skx_infra_guard.core.risk import RiskFactors, combine
from skx_infra_guard.parsers import gcloud as gcloud_parser

DOMAIN = "gcp"


def evaluate(command: str, ctx: RequestContext, engine: PolicyEngine) -> Verdict | None:
    parsed = gcloud_parser.parse(command)
    if parsed is None:
        return None

    # Most gcloud operations target one named resource ("group"-scale, not
    # broader). IAM policy mutations are the deliberate exception — a
    # binding on a project grants standing access across everything in it,
    # which is genuinely project-wide regardless of which environment tier
    # that project happens to represent (found during initial GCP-domain
    # testing: treating every "sql"/"container"/"kms" service as
    # project-wide made a routine `sql instances patch` blow up to CRITICAL
    # for no real reason — only IAM mutation actually earns that).
    blast_radius = "cluster_or_database" if parsed.touches_iam else "group"
    factors = RiskFactors(
        operation=parsed.operation,
        environment=ctx.environment,
        blast_radius=blast_radius,
        touches_iam=parsed.touches_iam,
        touches_secrets=parsed.touches_secrets,
        data_sensitivity="credential" if parsed.touches_secrets else "public",
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
    verdict.metadata.update(
        {
            "service": parsed.service,
            "verb": parsed.verb,
            "resource_hint": parsed.resource_hint,
            "touches_iam": parsed.touches_iam,
            "touches_secrets": parsed.touches_secrets,
        }
    )
    return verdict
