from skx_infra_guard.core.decision import OperationClass
from skx_infra_guard.parsers import helm as h


def test_template_is_read():
    assert h.parse("helm template ./chart").operation == OperationClass.READ


def test_diff_is_read():
    assert h.parse("helm diff upgrade my-release ./chart").operation == OperationClass.READ


def test_upgrade_is_change():
    parsed = h.parse("helm upgrade my-release ./chart")
    assert parsed.operation == OperationClass.CHANGE
    assert parsed.release_name == "my-release"


def test_install_is_change():
    assert h.parse("helm install my-release ./chart").operation == OperationClass.CHANGE


def test_rollback_is_change_not_destructive():
    # Per the brief: rollback is ASK, same tier as upgrade, not BLOCK.
    parsed = h.parse("helm rollback my-release 3")
    assert parsed.operation == OperationClass.CHANGE


def test_uninstall_is_destructive():
    parsed = h.parse("helm uninstall my-release")
    assert parsed.operation == OperationClass.DESTRUCTIVE
    assert parsed.release_name == "my-release"


def test_non_helm_command_returns_none():
    assert h.parse("kubectl get pods") is None


def test_unknown_subcommand_fails_safe_to_change():
    assert h.parse("helm somefuturesubcommand").operation == OperationClass.CHANGE
