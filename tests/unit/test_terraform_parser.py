from skx_infra_guard.core.decision import OperationClass
from skx_infra_guard.parsers import terraform as tf


def test_plan_is_read():
    assert tf.parse("terraform plan").operation == OperationClass.READ


def test_apply_is_change():
    assert tf.parse("terraform apply").operation == OperationClass.CHANGE


def test_destroy_is_destructive():
    parsed = tf.parse("terraform destroy")
    assert parsed.operation == OperationClass.DESTRUCTIVE
    assert parsed.subcommand == "destroy"


def test_tofu_alias_works_too():
    assert tf.parse("tofu destroy").operation == OperationClass.DESTRUCTIVE


def test_state_list_is_read_state_mv_is_change():
    assert tf.parse("terraform state list").operation == OperationClass.READ
    assert tf.parse("terraform state mv a b").operation == OperationClass.CHANGE


def test_state_show_exposes_secret_value_not_plain_read():
    # `state show` prints the resource's full attribute set — can include
    # plaintext secrets (DB passwords, API keys) unlike `state list`, which
    # only prints addresses. Found while building the Secrets domain.
    parsed = tf.parse("terraform state show google_sql_database_instance.main")
    assert parsed.exposes_secret_value is True
    assert parsed.operation == OperationClass.SECURITY_CRITICAL

    listed = tf.parse("terraform state list")
    assert listed.exposes_secret_value is False


def test_non_terraform_command_returns_none():
    assert tf.parse("kubectl get pods") is None


def test_apply_destroy_flag_is_destructive_like_destroy():
    # `terraform apply -destroy` is functionally `terraform destroy` — it
    # used to be classified purely by subcommand (apply == CHANGE), letting
    # a real destructive apply through at the wrong policy tier.
    parsed = tf.parse("terraform apply -destroy -auto-approve")
    assert parsed.operation == OperationClass.DESTRUCTIVE


def test_apply_destroy_equals_flag_is_also_destructive():
    parsed = tf.parse("terraform apply -destroy=true")
    assert parsed.operation == OperationClass.DESTRUCTIVE


def test_plain_apply_is_still_change_not_destructive():
    assert tf.parse("terraform apply -auto-approve").operation == OperationClass.CHANGE


def test_analyze_plan_output_no_changes():
    summary = tf.analyze_plan_output("No changes. Your infrastructure matches the configuration.")
    assert summary.no_changes is True
    assert summary.to_destroy == 0


def test_analyze_plan_output_extracts_counts():
    output = "Plan: 2 to add, 1 to change, 3 to destroy."
    summary = tf.analyze_plan_output(output)
    assert (summary.to_add, summary.to_change, summary.to_destroy) == (2, 1, 3)


def test_analyze_plan_output_flags_sensitive_resource_destruction():
    output = (
        "Plan: 0 to add, 0 to change, 1 to destroy.\n"
        "  # google_sql_database_instance.main will be destroyed\n"
    )
    summary = tf.analyze_plan_output(output)
    assert summary.destroys_sensitive_resource is True
    assert summary.blast_radius == "cluster_or_database"


def test_analyze_plan_output_not_a_plan_returns_none():
    assert tf.analyze_plan_output("Initializing the backend...") is None
