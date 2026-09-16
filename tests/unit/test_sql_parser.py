from skx_infra_guard.core.decision import OperationClass
from skx_infra_guard.parsers.sql import SqlRisk, parse_all, parse_statement


def test_select_with_where_is_safe():
    s = parse_statement("SELECT * FROM users WHERE id = 123")
    assert s.risk == SqlRisk.SAFE
    assert s.has_where is True
    assert s.operation == OperationClass.READ


def test_select_without_where_is_still_safe_but_unfiltered():
    s = parse_statement("SELECT * FROM users")
    assert s.risk == SqlRisk.SAFE
    assert s.has_where is False


def test_drop_table_is_critical():
    s = parse_statement("DROP TABLE users")
    assert s.risk == SqlRisk.CRITICAL
    assert s.operation == OperationClass.DESTRUCTIVE
    assert s.table == "users"


def test_truncate_is_critical():
    s = parse_statement("TRUNCATE TABLE logs")
    assert s.risk == SqlRisk.CRITICAL


def test_delete_without_where_is_critical():
    s = parse_statement("DELETE FROM sessions")
    assert s.risk == SqlRisk.CRITICAL
    assert s.has_where is False


def test_delete_with_where_is_safe():
    s = parse_statement("DELETE FROM sessions WHERE id = 1")
    assert s.risk == SqlRisk.SAFE


def test_delete_with_tautological_where_is_still_critical():
    s = parse_statement("DELETE FROM sessions WHERE 1=1")
    assert s.has_where is True
    assert s.where_is_tautology is True
    assert s.risk == SqlRisk.CRITICAL


def test_update_without_where_is_high():
    s = parse_statement("UPDATE users SET active = false")
    assert s.risk == SqlRisk.HIGH
    assert s.operation == OperationClass.CHANGE


def test_grant_is_high():
    s = parse_statement("GRANT ALL ON users TO someuser")
    assert s.risk == SqlRisk.HIGH


def test_create_table_is_medium():
    s = parse_statement("CREATE TABLE t (id int)")
    assert s.risk == SqlRisk.MEDIUM


def test_lowercase_drop_does_not_evade_detection():
    # A plain regex keyed on uppercase text (what a naive regex-based classifier
    # would do) is trivially evaded by case — sqlparse classifies by
    # token type, not by string casing (Skydropx brief section 32).
    s = parse_statement("drop table users")
    assert s.statement_type == "DROP"
    assert s.risk == SqlRisk.CRITICAL


def test_leading_comment_does_not_evade_drop_detection():
    s = parse_statement("-- looks innocuous\nDROP TABLE users")
    assert s.statement_type == "DROP"
    assert s.risk == SqlRisk.CRITICAL


def test_mixed_case_delete_without_where_does_not_evade_detection():
    s = parse_statement("DeLeTe FrOm users")
    assert s.statement_type == "DELETE"
    assert s.risk == SqlRisk.CRITICAL


def test_multi_statement_split_finds_the_dangerous_one():
    statements = parse_all("SELECT 1; DROP TABLE users; SELECT 2")
    risks = [s.risk for s in statements]
    assert SqlRisk.CRITICAL in risks
