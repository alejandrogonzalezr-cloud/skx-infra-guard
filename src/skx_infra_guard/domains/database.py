from __future__ import annotations

from skx_infra_guard.core.context import RequestContext
from skx_infra_guard.core.decision import Verdict
from skx_infra_guard.core.policy import PolicyEngine
from skx_infra_guard.core.risk import RiskFactors, combine
from skx_infra_guard.parsers import shell as shell_parser
from skx_infra_guard.parsers import sql as sql_parser

DOMAIN = "database"

_SQL_TO_SENSITIVITY_DEFAULT = "internal"  # no data catalog wired yet — see
# docs/skydropx-architecture.md #7.3. Overridable per-table via
# policies/data-sensitivity.yaml once that catalog exists.


def evaluate(command: str, ctx: RequestContext, engine: PolicyEngine) -> Verdict | None:
    client = shell_parser.detect_db_client(command)
    if client is None:
        return None

    sql_text = shell_parser.extract_inline_sql(command) or command
    statements = sql_parser.parse_all(sql_text)
    if not statements:
        return None

    # Worst statement wins, matching the engine's "any CRITICAL blocks
    # the whole command" behavior.
    worst = max(statements, key=lambda s: list(sql_parser.SqlRisk).index(s.risk))

    unfiltered = not worst.has_where or worst.where_is_tautology
    sensitivity = _SQL_TO_SENSITIVITY_DEFAULT
    if worst.operation.value == "read" and unfiltered:
        # An unfiltered SELECT doesn't carry destructive blast radius, but
        # it does read more than a scoped one — surface that in the risk
        # score for audit visibility (Skydropx brief section 14), without
        # ever blocking the read itself (policy.py never escalates READ).
        sensitivity = "sensitive"

    factors = RiskFactors(
        operation=worst.operation,
        environment=ctx.environment,
        blast_radius="cluster_or_database" if unfiltered else "group",
        data_sensitivity=sensitivity,
    )
    risk = combine(factors)

    verdict = engine.evaluate(
        domain=DOMAIN,
        operation=worst.operation,
        resource_type=worst.statement_type.lower(),
        risk=risk,
        environment=ctx.environment,
    )
    verdict.metadata.update(
        {
            "db_client": client,
            "statement_type": worst.statement_type,
            "has_where": worst.has_where,
            "where_is_tautology": worst.where_is_tautology,
            "table": worst.table,
            "reason_detail": worst.risk_reason,
        }
    )
    if not verdict.reason:
        verdict.reason = worst.risk_reason
    return verdict
