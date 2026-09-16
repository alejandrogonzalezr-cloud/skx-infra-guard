from __future__ import annotations

import shlex

from skx_infra_guard.core.context import RequestContext, touches_production_from_elsewhere
from skx_infra_guard.core.decision import OperationClass, Verdict
from skx_infra_guard.core.policy import PolicyEngine
from skx_infra_guard.core.risk import RiskFactors, combine
from skx_infra_guard.parsers import shell as shell_parser
from skx_infra_guard.parsers import sql as sql_parser

DOMAIN = "database"

_SQL_TO_SENSITIVITY_DEFAULT = "internal"  # no data catalog wired yet — see
# docs/skydropx-architecture.md #7.3. Overridable per-table via
# policies/data-sensitivity.yaml once that catalog exists.


def _extract_host(command: str) -> str | None:
    """Pull the `-h`/`--host` value out of a psql/mysql-style invocation —
    a more precise resource hint than the whole command text, since SQL
    payloads can legitimately contain the literal word "production" as
    ordinary data (e.g. `WHERE environment = 'production'`) without the
    command actually targeting a production host."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    for flag in ("-h", "--host"):
        if flag in tokens:
            idx = tokens.index(flag)
            if idx + 1 < len(tokens):
                return tokens[idx + 1]
    return None


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

    # Same sandbox/dev-reaching-into-production escalation kubernetes.py
    # applies to a namespace argument, generalized here (found only wired
    # for Kubernetes in the 2026-09 review) — e.g. `psql -h prod-db.internal
    # -c 'DROP TABLE users;'` run from a sandbox session.
    touches_prod_elsewhere = worst.operation != OperationClass.READ and touches_production_from_elsewhere(
        _extract_host(command), ctx.environment
    )
    factors = RiskFactors(
        operation=worst.operation,
        environment=ctx.environment,
        blast_radius="cluster_or_database" if unfiltered else "group",
        data_sensitivity=sensitivity,
        touches_production_from_elsewhere=touches_prod_elsewhere,
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
