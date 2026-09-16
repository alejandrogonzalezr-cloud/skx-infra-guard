from skx_infra_guard.core.decision import OperationClass
from skx_infra_guard.parsers import redis as r


def test_get_is_read():
    parsed = r.parse("redis-cli GET foo")
    assert parsed.operation == OperationClass.READ
    assert parsed.command == "get"


def test_get_is_case_insensitive():
    assert r.parse("redis-cli get foo").operation == OperationClass.READ


def test_scan_and_keys_are_read():
    assert r.parse("redis-cli SCAN 0").operation == OperationClass.READ
    assert r.parse("redis-cli KEYS *").operation == OperationClass.READ


def test_set_is_change():
    parsed = r.parse("redis-cli SET foo bar")
    assert parsed.operation == OperationClass.CHANGE


def test_del_is_destructive():
    parsed = r.parse("redis-cli DEL foo")
    assert parsed.operation == OperationClass.DESTRUCTIVE
    assert parsed.always_blocked is False


def test_flushall_is_always_blocked():
    parsed = r.parse("redis-cli FLUSHALL")
    assert parsed.always_blocked is True
    assert parsed.operation == OperationClass.DESTRUCTIVE


def test_flushdb_is_always_blocked():
    parsed = r.parse("redis-cli FLUSHDB")
    assert parsed.always_blocked is True


def test_non_redis_command_returns_none():
    assert r.parse("psql -c 'SELECT 1'") is None


def test_key_hint_extraction():
    parsed = r.parse("redis-cli GET session:abc123")
    assert parsed.key_hint == "session:abc123"


def test_unrecognized_command_fails_safe_to_change():
    parsed = r.parse("redis-cli SOMEFUTURECOMMAND arg")
    assert parsed.operation == OperationClass.CHANGE
