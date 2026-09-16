from skx_infra_guard.core.decision import OperationClass
from skx_infra_guard.parsers import kubernetes as k


def test_get_pods_is_read():
    parsed = k.parse("kubectl get pods")
    assert parsed.operation == OperationClass.READ
    assert parsed.resource_type == "pods"


def test_delete_namespace_is_destructive():
    parsed = k.parse("kubectl delete namespace production")
    assert parsed.operation == OperationClass.DESTRUCTIVE
    assert parsed.resource_type == "namespace"
    assert parsed.resource_name == "production"


def test_apply_is_change():
    parsed = k.parse("kubectl apply -f deployment.yaml")
    assert parsed.operation == OperationClass.CHANGE


def test_exec_resource_type_is_pod_not_the_pod_name():
    parsed = k.parse("kubectl exec my-pod-123 -- ls")
    assert parsed.resource_type == "pod"
    assert parsed.resource_name == "my-pod-123"


def test_drain_resource_type_is_node_not_the_node_name():
    parsed = k.parse("kubectl drain node-1 --ignore-daemonsets")
    assert parsed.resource_type == "node"
    assert parsed.resource_name == "node-1"
    assert parsed.blast_radius == "cluster_or_database"


def test_get_secret_metadata_only_is_read():
    parsed = k.parse("kubectl get secret db-creds")
    assert parsed.operation == OperationClass.READ
    assert parsed.exposes_secret_value is False


def test_get_secret_yaml_exposes_value():
    parsed = k.parse("kubectl get secret db-creds -o yaml")
    assert parsed.exposes_secret_value is True
    assert parsed.operation == OperationClass.SECURITY_CRITICAL


def test_rollout_status_is_read_rollout_restart_is_change():
    assert k.parse("kubectl rollout status deployment/api").operation == OperationClass.READ
    assert k.parse("kubectl rollout restart deployment/api").operation == OperationClass.CHANGE


def test_non_kubectl_command_returns_none():
    assert k.parse("git status") is None


def test_namespace_flag_extraction():
    parsed = k.parse("kubectl get pods -n production")
    assert parsed.namespace == "production"


def test_apply_dash_f_value_is_not_mistaken_for_a_resource_type():
    # Found during the 2026-09-15 review: `x.yaml` was slipping through as
    # if it were a positional resource type.
    parsed = k.parse("kubectl apply -f x.yaml -n stg-labels-light")
    assert parsed.resource_type is None
    assert parsed.namespace == "stg-labels-light"
