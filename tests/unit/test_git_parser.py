from skx_infra_guard.core.decision import OperationClass
from skx_infra_guard.parsers import git as g


def test_force_push_detected():
    parsed = g.parse("git push origin main --force")
    assert parsed.resource_type == "force_push"
    assert parsed.operation == OperationClass.DESTRUCTIVE


def test_dash_f_force_push_detected():
    parsed = g.parse("git push -f origin main")
    assert parsed.resource_type == "force_push"


def test_push_to_protected_branch_detected():
    parsed = g.parse("git push origin main")
    assert parsed.resource_type == "protected_branch_push"


def test_push_to_feature_branch_is_plain_change():
    parsed = g.parse("git push origin my-feature-branch")
    assert parsed.resource_type is None
    assert parsed.operation == OperationClass.CHANGE


def test_hard_reset_detected():
    parsed = g.parse("git reset --hard HEAD~3")
    assert parsed.resource_type == "hard_reset"


def test_clean_force_detected():
    parsed = g.parse("git clean -fd")
    assert parsed.resource_type == "clean_force"


def test_no_verify_detected():
    parsed = g.parse('git commit -m "test" --no-verify')
    assert parsed.resource_type == "no_verify"


def test_delete_remote_branch_detected():
    parsed = g.parse("git push origin --delete feature-branch")
    assert parsed.resource_type == "delete_remote_branch"


def test_status_is_read():
    assert g.parse("git status").operation == OperationClass.READ


def test_non_git_command_returns_none():
    assert g.parse("kubectl get pods") is None
