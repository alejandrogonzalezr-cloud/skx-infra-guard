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
