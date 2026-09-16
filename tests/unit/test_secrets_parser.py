from skx_infra_guard.parsers import secrets as s


def test_printenv_of_secret_var_detected():
    exposure = s.detect_env_var_exposure("printenv AWS_SECRET_ACCESS_KEY")
    assert exposure is not None
    assert exposure.var_hint == "AWS_SECRET_ACCESS_KEY"


def test_printenv_of_token_var_detected():
    assert s.detect_env_var_exposure("printenv DATABASE_URL") is not None


def test_printenv_of_ordinary_var_not_detected():
    assert s.detect_env_var_exposure("printenv PATH") is None
    assert s.detect_env_var_exposure("printenv HOME") is None


def test_env_pipe_grep_secret_detected():
    assert s.detect_env_var_exposure("env | grep TOKEN") is not None
    assert s.detect_env_var_exposure("env | grep SECRET_KEY") is not None


def test_env_pipe_grep_ordinary_not_detected():
    assert s.detect_env_var_exposure("env | grep PATH") is None


def test_unrelated_command_not_detected():
    assert s.detect_env_var_exposure("kubectl get pods") is None
