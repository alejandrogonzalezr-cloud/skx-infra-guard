"""Terraform / OpenTofu command parser + plan-content analyzer.

Implements real (text-based) plan-content analysis to verify how many resources 
would be added/changed/destroyed, and whether any of the destroyed addresses 
look like a database, IAM, or network resource, preventing un-audited destructive 
applies from running within the approval window.

This parses the human-readable plan output Terraform already prints to detect 
modifications and resource actions.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from skx_infra_guard.core.decision import OperationClass

_READ_SUBCOMMANDS = {
    "init", "plan", "validate", "fmt", "show", "output", "providers", "version",
}
_READ_STATE_SUBCOMMANDS = {"list"}  # only lists resource ADDRESSES, no values
# `terraform state show <address>` prints the resource's full attribute set
# — including anything Terraform doesn't mark `sensitive` in the provider
# schema, which for many real-world resources (DB passwords, API keys set
# as plain string attributes) means plaintext secret exposure. Same
# metadata-vs-value distinction as `kubectl get secret -o yaml`
# (docs/policy-model.md #11) — found while building the Secrets domain.
_SECRET_VALUE_STATE_SUBCOMMANDS = {"show"}
_CHANGE_SUBCOMMANDS = {"apply", "import", "refresh", "taint", "untaint"}
_DESTRUCTIVE_SUBCOMMANDS = {"destroy", "force-unlock"}

_PLAN_SUMMARY_RE = re.compile(
    r"Plan:\s*(\d+)\s+to add,\s*(\d+)\s+to change,\s*(\d+)\s+to destroy", re.IGNORECASE
)
_NO_CHANGES_RE = re.compile(r"No changes\.", re.IGNORECASE)
_DESTROY_ADDRESS_RE = re.compile(r"^\s*#\s*(\S+)\s+will be destroyed", re.IGNORECASE | re.MULTILINE)

_SENSITIVE_ADDRESS_HINTS = (
    "google_sql_database",
    "google_sql_database_instance",
    "aws_db_instance",
    "aws_rds",
    "google_project_iam",
    "google_service_account",
    "aws_iam",
    "google_compute_network",
    "google_compute_firewall",
    "aws_security_group",
    "google_kms",
    "aws_kms",
)


@dataclass
class TerraformCommand:
    subcommand: str
    operation: OperationClass
    exposes_secret_value: bool = False


@dataclass
class PlanSummary:
    to_add: int
    to_change: int
    to_destroy: int
    no_changes: bool
    destroyed_addresses: tuple[str, ...]
    destroys_sensitive_resource: bool

    @property
    def blast_radius(self) -> str:
        if self.to_destroy == 0:
            return "single" if (self.to_add + self.to_change) <= 1 else "group"
        if self.destroys_sensitive_resource or self.to_destroy > 3:
            return "cluster_or_database"
        return "namespace_or_schema" if self.to_destroy > 1 else "group"


def is_terraform_command(command: str) -> bool:
    return bool(re.match(r"^\s*(terraform|tofu)\s", command))


def parse(command: str) -> TerraformCommand | None:
    if not is_terraform_command(command):
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    rest = tokens[1:]
    if not rest:
        return None

    subcommand = rest[0]
    exposes_secret_value = False
    if subcommand == "state":
        # `terraform state list` only prints resource addresses (safe);
        # `state show <addr>` prints the full attribute set (can expose
        # secrets); `state mv|rm|push` mutate.
        sub2 = rest[1] if len(rest) > 1 else ""
        if sub2 in _SECRET_VALUE_STATE_SUBCOMMANDS:
            operation = OperationClass.SECURITY_CRITICAL
            exposes_secret_value = True
        elif sub2 in _READ_STATE_SUBCOMMANDS:
            operation = OperationClass.READ
        else:
            operation = OperationClass.CHANGE
        subcommand = f"state:{sub2}" if sub2 else "state"
    elif subcommand in _DESTRUCTIVE_SUBCOMMANDS:
        operation = OperationClass.DESTRUCTIVE
    elif subcommand in _CHANGE_SUBCOMMANDS:
        operation = OperationClass.CHANGE
    elif subcommand in _READ_SUBCOMMANDS:
        operation = OperationClass.READ
    else:
        operation = OperationClass.CHANGE  # unknown subcommand: fail-safe

    return TerraformCommand(
        subcommand=subcommand, operation=operation, exposes_secret_value=exposes_secret_value
    )


def analyze_plan_output(output: str) -> PlanSummary | None:
    """Parse the human-readable output of `terraform plan`/`apply`.

    Returns None if the output doesn't look like plan output at all (so
    callers can distinguish "not a plan" from "an empty/no-op plan").
    """
    if _NO_CHANGES_RE.search(output):
        return PlanSummary(0, 0, 0, True, (), False)

    m = _PLAN_SUMMARY_RE.search(output)
    if not m:
        return None

    to_add, to_change, to_destroy = (int(g) for g in m.groups())
    destroyed = tuple(_DESTROY_ADDRESS_RE.findall(output))
    destroys_sensitive = any(
        hint in addr for addr in destroyed for hint in _SENSITIVE_ADDRESS_HINTS
    )

    return PlanSummary(
        to_add=to_add,
        to_change=to_change,
        to_destroy=to_destroy,
        no_changes=False,
        destroyed_addresses=destroyed,
        destroys_sensitive_resource=destroys_sensitive,
    )
