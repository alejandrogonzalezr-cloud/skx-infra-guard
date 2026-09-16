from skx_infra_guard.domains import shell_safety


def test_rm_rf_root_blocked():
    assert shell_safety.check("rm -rf /") is not None


def test_fork_bomb_blocked():
    assert shell_safety.check(":(){ :|:& };:") is not None


def test_dd_to_block_device_blocked():
    assert shell_safety.check("dd if=/dev/zero of=/dev/sda") is not None


def test_iptables_flush_blocked():
    assert shell_safety.check("iptables -F") is not None


def test_cat_aws_credentials_blocked():
    assert shell_safety.check("cat ~/.aws/credentials") is not None


def test_history_clear_blocked():
    assert shell_safety.check("history -c") is not None


def test_ordinary_ls_is_fine():
    assert shell_safety.check("ls -la") is None


def test_git_status_is_fine():
    assert shell_safety.check("git status") is None
