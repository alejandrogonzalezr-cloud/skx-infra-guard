from skx_infra_guard.core.decision import Decision, EnvironmentTier
from skx_infra_guard.domains import file_guard


def test_write_to_etc_hosts_blocked():
    verdict = file_guard.evaluate_write(["/etc/hosts"], EnvironmentTier.DEV)
    assert verdict is not None and verdict.decision == Decision.BLOCK


def test_write_to_ssh_authorized_keys_blocked():
    verdict = file_guard.evaluate_write(["~/.ssh/authorized_keys"], EnvironmentTier.DEV)
    assert verdict is not None and verdict.decision == Decision.BLOCK


def test_write_to_tfstate_blocked():
    verdict = file_guard.evaluate_write(["/project/terraform.tfstate"], EnvironmentTier.PRODUCTION)
    assert verdict is not None and verdict.decision == Decision.BLOCK


def test_write_to_project_file_is_fine():
    assert file_guard.evaluate_write(["/home/user/project/src/main.py"], EnvironmentTier.DEV) is None


def test_read_aws_credentials_blocked():
    verdict = file_guard.evaluate_read(["~/.aws/credentials"], EnvironmentTier.DEV)
    assert verdict is not None and verdict.decision == Decision.BLOCK


def test_read_env_file_blocked():
    verdict = file_guard.evaluate_read([".env.production"], EnvironmentTier.DEV)
    assert verdict is not None and verdict.decision == Decision.BLOCK


def test_read_ordinary_file_is_fine():
    assert file_guard.evaluate_read(["/tmp/test.txt"], EnvironmentTier.DEV) is None


def test_relative_path_traversal_resolved_against_cwd_blocks_etc_write():
    # "../../etc/passwd" never starts with the literal "/etc/" on its own —
    # without resolving against cwd first, this used to slide past every
    # anchored pattern untouched (found in the 2026-09 review).
    verdict = file_guard.evaluate_write(["../../etc/passwd"], EnvironmentTier.DEV, cwd="/home/agent")
    assert verdict is not None and verdict.decision == Decision.BLOCK


def test_relative_path_traversal_resolved_against_cwd_blocks_shadow_read():
    verdict = file_guard.evaluate_read(["../../etc/shadow"], EnvironmentTier.DEV, cwd="/home/agent")
    assert verdict is not None and verdict.decision == Decision.BLOCK


def test_relative_path_without_traversal_still_fine():
    assert file_guard.evaluate_write(["notes.txt"], EnvironmentTier.DEV, cwd="/home/agent/project") is None


def test_absolute_path_ignores_cwd_as_before():
    verdict = file_guard.evaluate_write(["/etc/hosts"], EnvironmentTier.DEV, cwd="/home/agent/project")
    assert verdict is not None and verdict.decision == Decision.BLOCK


def test_read_tfstate_now_blocked_consolidated_list():
    # .tfstate was only in the WRITE list before consolidation — reading it
    # can expose plaintext secrets just as easily (found in the 2026-09
    # review).
    verdict = file_guard.evaluate_read(["/project/terraform.tfstate"], EnvironmentTier.DEV)
    assert verdict is not None and verdict.decision == Decision.BLOCK


def test_read_ssh_known_hosts_now_blocked_consolidated_list():
    verdict = file_guard.evaluate_read(["~/.ssh/known_hosts"], EnvironmentTier.DEV)
    assert verdict is not None and verdict.decision == Decision.BLOCK


def test_read_ssh_pub_key_wildcard_now_blocked_consolidated_list():
    verdict = file_guard.evaluate_read(["~/.ssh/id_ed25519.pub"], EnvironmentTier.DEV)
    assert verdict is not None and verdict.decision == Decision.BLOCK
