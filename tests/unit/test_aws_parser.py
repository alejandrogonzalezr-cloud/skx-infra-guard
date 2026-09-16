from skx_infra_guard.core.decision import OperationClass
from skx_infra_guard.parsers import aws as a


def test_describe_instances_is_read():
    parsed = a.parse("aws ec2 describe-instances")
    assert parsed.operation == OperationClass.READ


def test_ls_is_read():
    assert a.parse("aws s3 ls").operation == OperationClass.READ


def test_create_user_is_iam_security_critical():
    parsed = a.parse("aws iam create-user --user-name attacker")
    assert parsed.operation == OperationClass.SECURITY_CRITICAL
    assert parsed.touches_iam is True


def test_attach_role_policy_is_iam_security_critical():
    parsed = a.parse("aws iam attach-role-policy --role-name x --policy-arn y")
    assert parsed.touches_iam is True


def test_assume_role_is_security_critical():
    parsed = a.parse("aws sts assume-role --role-arn arn:aws:iam::123:role/admin --role-session-name x")
    assert parsed.operation == OperationClass.SECURITY_CRITICAL
    assert parsed.touches_iam is True


def test_terminate_instances_is_destructive():
    parsed = a.parse("aws ec2 terminate-instances --instance-ids i-1234")
    assert parsed.operation == OperationClass.DESTRUCTIVE


def test_s3_rb_is_destructive():
    assert a.parse("aws s3 rb s3://my-bucket").operation == OperationClass.DESTRUCTIVE


def test_create_bucket_is_change_not_iam():
    parsed = a.parse("aws s3api create-bucket --bucket my-bucket")
    assert parsed.operation == OperationClass.CHANGE
    assert parsed.touches_iam is False


def test_non_aws_command_returns_none():
    assert a.parse("gcloud compute instances list") is None


def test_bare_service_no_verb_fails_safe_to_change():
    assert a.parse("aws configure").operation == OperationClass.CHANGE
