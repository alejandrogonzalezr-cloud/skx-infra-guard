from skx_infra_guard.core.decision import OperationClass
from skx_infra_guard.parsers import mongodb as m


def test_find_is_read():
    parsed = m.parse("mongosh mydb --eval 'db.users.find({status: \"active\"})'")
    assert parsed.operation == OperationClass.READ
    assert "find" in parsed.methods_found


def test_insert_one_is_change():
    parsed = m.parse("mongosh mydb --eval 'db.users.insertOne({name: \"x\"})'")
    assert parsed.operation == OperationClass.CHANGE


def test_delete_one_is_destructive():
    parsed = m.parse("mongosh mydb --eval 'db.users.deleteOne({_id: 1})'")
    assert parsed.operation == OperationClass.DESTRUCTIVE
    assert parsed.always_blocked is False


def test_drop_database_is_always_blocked():
    parsed = m.parse("mongosh mydb --eval 'db.dropDatabase()'")
    assert parsed.always_blocked is True
    assert parsed.operation == OperationClass.DESTRUCTIVE


def test_delete_many_empty_filter_is_always_blocked():
    parsed = m.parse("mongosh mydb --eval 'db.users.deleteMany({})'")
    assert parsed.always_blocked is True


def test_delete_many_with_filter_is_not_always_blocked():
    parsed = m.parse("mongosh mydb --eval 'db.users.deleteMany({status: \"inactive\"})'")
    assert parsed.operation == OperationClass.DESTRUCTIVE
    assert parsed.always_blocked is False


def test_remove_empty_filter_is_always_blocked():
    parsed = m.parse("mongosh mydb --eval 'db.users.remove({})'")
    assert parsed.always_blocked is True


def test_legacy_mongo_client_also_detected():
    parsed = m.parse("mongo mydb --eval 'db.users.find()'")
    assert parsed is not None
    assert parsed.operation == OperationClass.READ


def test_non_mongo_command_returns_none():
    assert m.parse("redis-cli GET foo") is None


def test_bare_invocation_fails_safe_to_change():
    parsed = m.parse("mongosh mongodb://localhost:27017/mydb")
    assert parsed.operation == OperationClass.CHANGE
