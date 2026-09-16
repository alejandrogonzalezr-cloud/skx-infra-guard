"""SQL parser.

This module uses `sqlparse` to tokenize real SQL instead of grepping text,
so a comment stuck in the middle of `DR/**/OP TABLE` or a semicolon-chained
second statement doesn't quietly slip past a regex anchor.

Risk taxonomy is mapped to CRITICAL/HIGH/ELEVATED/MEDIUM/SAFE tiers 
(docs/policy-model.md #8), ensuring a structured classification of SQL commands.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

import sqlparse
from sqlparse.sql import Where
from sqlparse.tokens import DDL, DML, Keyword

from skx_infra_guard.core.decision import OperationClass


class SqlRisk(str, Enum):
    SAFE = "safe"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_DESTRUCTIVE_DDL = {"DROP", "TRUNCATE"}
_ADDITIVE_DDL = {"CREATE", "ALTER"}
_TAUTOLOGY_RE = re.compile(r"^\s*(1\s*=\s*1|true|'1'\s*=\s*'1')\s*$", re.IGNORECASE)


@dataclass
class SqlStatement:
    statement_type: str  # SELECT/INSERT/UPDATE/DELETE/CREATE/ALTER/DROP/TRUNCATE/GRANT/REVOKE/OTHER
    has_where: bool
    where_is_tautology: bool
    table: str | None
    risk: SqlRisk
    risk_reason: str
    operation: OperationClass


def split_statements(sql_text: str) -> list[str]:
    return [s.strip() for s in sqlparse.split(sql_text) if s.strip()]


def _statement_type(parsed: sqlparse.sql.Statement) -> str:
    for token in parsed.tokens:
        if token.ttype in (DML, DDL):
            return token.value.upper()
        # GRANT/REVOKE land under Keyword.DCL, a sub-type of Keyword — `in`
        # walks the sqlparse token-type hierarchy, `is` would miss it.
        if token.ttype in Keyword and token.value.upper() in ("GRANT", "REVOKE"):
            return token.value.upper()
    return "OTHER"


def _find_where(parsed: sqlparse.sql.Statement) -> Where | None:
    for token in parsed.tokens:
        if isinstance(token, Where):
            return token
    return None


def _where_is_tautology(where: Where) -> bool:
    # Strip the leading WHERE keyword, check what's left against known
    # always-true shapes. Deliberately conservative: only catches the
    # textbook cases (1=1, TRUE), not full boolean-expression evaluation.
    body = "".join(str(t) for t in where.tokens[1:]).strip()
    return bool(_TAUTOLOGY_RE.match(body))


def _extract_table(parsed: sqlparse.sql.Statement, statement_type: str) -> str | None:
    tokens = [t for t in parsed.flatten() if not t.is_whitespace]
    keywords_before_table = {
        "DELETE": "FROM",
        "UPDATE": "UPDATE",
        "INSERT": "INTO",
        "DROP": None,  # handled specially below
        "TRUNCATE": "TRUNCATE",
    }
    marker = keywords_before_table.get(statement_type)
    if statement_type == "DROP":
        # DROP TABLE <name> / DROP DATABASE <name> / ...
        seen_drop = False
        seen_object_kind = False
        for tok in tokens:
            up = tok.value.upper()
            if up == "DROP":
                seen_drop = True
                continue
            if seen_drop and not seen_object_kind and up in (
                "TABLE", "DATABASE", "SCHEMA", "INDEX", "VIEW", "SEQUENCE", "TRIGGER", "FUNCTION", "PROCEDURE",
            ):
                seen_object_kind = True
                continue
            if seen_object_kind:
                return tok.value.strip('`"[]')
        return None

    if marker is None:
        return None
    for i, tok in enumerate(tokens):
        if tok.value.upper() == marker:
            for nxt in tokens[i + 1:]:
                if nxt.value.upper() == "SET":
                    break
                return nxt.value.strip('`"[]')
    return None


def _classify_risk(statement_type: str, has_where: bool, is_tautology: bool) -> tuple[SqlRisk, str]:
    if statement_type in _DESTRUCTIVE_DDL:
        return SqlRisk.CRITICAL, f"{statement_type} statement destroys data permanently"
    if statement_type == "DELETE" and (not has_where or is_tautology):
        return SqlRisk.CRITICAL, "DELETE without an effective WHERE clause will delete all rows"
    if statement_type == "UPDATE" and (not has_where or is_tautology):
        return SqlRisk.HIGH, "UPDATE without an effective WHERE clause will update all rows"
    if statement_type in ("GRANT", "REVOKE"):
        return SqlRisk.HIGH, f"{statement_type} modifies database permissions"
    if statement_type in _ADDITIVE_DDL:
        return SqlRisk.MEDIUM, f"{statement_type} is a schema modification"
    return SqlRisk.SAFE, "read-only or filtered statement"


def _operation_for(statement_type: str, risk: SqlRisk) -> OperationClass:
    if statement_type == "SELECT" or statement_type in ("SHOW", "DESCRIBE", "EXPLAIN"):
        return OperationClass.READ
    if risk in (SqlRisk.CRITICAL,):
        return OperationClass.DESTRUCTIVE
    return OperationClass.CHANGE


def parse_statement(sql_text: str) -> SqlStatement:
    parsed = sqlparse.parse(sql_text)[0] if sqlparse.parse(sql_text) else sqlparse.sql.Statement([])
    statement_type = _statement_type(parsed)
    where = _find_where(parsed)
    has_where = where is not None
    is_tautology = _where_is_tautology(where) if where is not None else False
    table = _extract_table(parsed, statement_type)
    risk, reason = _classify_risk(statement_type, has_where, is_tautology)
    operation = _operation_for(statement_type, risk)

    return SqlStatement(
        statement_type=statement_type,
        has_where=has_where,
        where_is_tautology=is_tautology,
        table=table,
        risk=risk,
        risk_reason=reason,
        operation=operation,
    )


def parse_all(sql_text: str) -> list[SqlStatement]:
    return [parse_statement(s) for s in split_statements(sql_text)]
