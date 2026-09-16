from skx_infra_guard.core.decision import OperationClass
from skx_infra_guard.parsers import gcloud as g


def test_describe_is_read():
    parsed = g.parse("gcloud sql instances describe my-instance")
    assert parsed.operation == OperationClass.READ
    assert parsed.service == "sql"
    assert parsed.verb == "describe"


def test_list_is_read():
    assert g.parse("gcloud compute instances list").operation == OperationClass.READ


def test_patch_is_change():
    parsed = g.parse("gcloud sql instances patch my-instance --tier=db-n1-standard-2")
    assert parsed.operation == OperationClass.CHANGE
    assert parsed.verb == "patch"


def test_delete_is_destructive():
    parsed = g.parse("gcloud sql instances delete my-instance")
    assert parsed.operation == OperationClass.DESTRUCTIVE
    assert parsed.verb == "delete"


def test_compute_instances_delete_is_destructive():
    parsed = g.parse("gcloud compute instances delete my-vm")
    assert parsed.operation == OperationClass.DESTRUCTIVE


def test_add_iam_policy_binding_is_security_critical_regardless_of_resource_noun():
    for cmd in (
        "gcloud projects add-iam-policy-binding my-project --member=user:x --role=roles/owner",
        "gcloud kms keys add-iam-policy-binding my-key --member=user:x --role=roles/owner",
        "gcloud secrets add-iam-policy-binding my-secret --member=user:x --role=roles/owner",
    ):
        parsed = g.parse(cmd)
        assert parsed.operation == OperationClass.SECURITY_CRITICAL, cmd
        assert parsed.touches_iam is True, cmd


def test_set_iam_policy_is_security_critical():
    parsed = g.parse("gcloud projects set-iam-policy my-project policy.json")
    assert parsed.touches_iam is True


def test_get_iam_policy_is_read_not_security_critical():
    parsed = g.parse("gcloud projects get-iam-policy my-project")
    assert parsed.operation == OperationClass.READ
    assert parsed.touches_iam is False


def test_secrets_versions_access_exposes_value():
    parsed = g.parse("gcloud secrets versions access latest --secret=db-password")
    assert parsed.touches_secrets is True
    assert parsed.operation == OperationClass.SECURITY_CRITICAL


def test_secrets_describe_does_not_expose_value():
    parsed = g.parse("gcloud secrets describe db-password")
    assert parsed.touches_secrets is False
    assert parsed.operation == OperationClass.READ


def test_non_gcloud_command_returns_none():
    assert g.parse("kubectl get pods") is None


def test_unknown_verb_fails_safe_to_change_not_read():
    parsed = g.parse("gcloud auth login")
    assert parsed.operation == OperationClass.CHANGE
