"""Kubernetes / GKE command parser.

Parses kubectl commands to classify get/describe/logs as read, delete/drain/
cordon/taint as destructive, and exec on prod namespaces as blocked. This
module turns that into a typed parse result the Risk/Policy Engines can use,
and adds:

1. Blast radius (pod < deployment < namespace < cluster) — Skydropx brief
   section 21.
2. The metadata-vs-value distinction for secrets (section 16): `kubectl get
   secret foo` only confirms existence; `-o yaml`/`-o json` exposes the
   actual (base64) value.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from skx_infra_guard.core.decision import OperationClass

_READ_VERBS = {
    "get", "describe", "logs", "top", "explain", "version",
    "cluster-info", "api-resources", "api-versions",
}
_CHANGE_VERBS = {
    "apply", "patch", "edit", "scale", "label", "annotate", "set",
    "expose", "autoscale", "create", "run",
}
_ROLLOUT_CHANGE_SUBCOMMANDS = {"restart", "undo", "pause", "resume"}
_DESTRUCTIVE_VERBS = {"delete", "drain", "cordon", "uncordon", "taint", "replace"}

# Verbs whose first positional argument is a resource NAME, not a resource
# TYPE (`kubectl exec <pod>`, `kubectl drain <node>`) — without this, the
# generic "positional[0] = resource_type" rule below would misread the name
# itself as a type.
_IMPLICIT_RESOURCE_TYPE = {
    "exec": "pod",
    "logs": "pod",
    "drain": "node",
    "cordon": "node",
    "uncordon": "node",
    "taint": "node",
}

_VALUE_EXPOSING_OUTPUT = re.compile(r"^(yaml|json)$", re.IGNORECASE)

# Flags that consume the NEXT token as their value — without this,
# `kubectl apply -f x.yaml -n prod` mis-extracts "x.yaml" as if it were a
# positional resource type (found during the 2026-09-15 review, while
# validating the touches_production_from_elsewhere fix).
_VALUE_FLAGS = {
    "-n", "--namespace", "-o", "--output", "-f", "--filename", "-l", "--selector",
    "-c", "--container", "--context", "--kubeconfig", "-k", "--kustomize",
    "--field-selector", "--grace-period", "--timeout", "--replicas",
}


@dataclass
class KubectlCommand:
    verb: str
    resource_type: str | None
    resource_name: str | None
    namespace: str | None
    operation: OperationClass
    blast_radius: str
    exposes_secret_value: bool


def _extract_flag_value(tokens: list[str], *names: str) -> str | None:
    for i, tok in enumerate(tokens):
        for name in names:
            if tok == name and i + 1 < len(tokens):
                return tokens[i + 1]
            if tok.startswith(name + "="):
                return tok.split("=", 1)[1]
    return None


def _positional_args(tokens: list[str]) -> list[str]:
    """Everything left after stripping flags AND the separate values that
    belong to them (see _VALUE_FLAGS) — a bare `t.startswith("-")` filter
    lets a flag's own value (e.g. `x.yaml` in `-f x.yaml`) slip through as
    if it were a positional resource type/name."""
    result: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("-"):
            if "=" in tok:
                i += 1
                continue
            if tok in _VALUE_FLAGS and i + 1 < len(tokens):
                i += 2
                continue
            i += 1
            continue
        result.append(tok)
        i += 1
    return result


def is_kubectl_command(command: str) -> bool:
    return bool(re.match(r"^\s*kubectl\s", command))


def parse(command: str) -> KubectlCommand | None:
    if not is_kubectl_command(command):
        return None

    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    # tokens[0] == "kubectl"
    rest = [t for t in tokens[1:] if t]
    if not rest:
        return None

    verb = rest[0]
    namespace = _extract_flag_value(rest, "-n", "--namespace")

    output_format = _extract_flag_value(rest, "-o", "--output")
    exposes_secret_value = False

    resource_type: str | None = None
    resource_name: str | None = None
    positional = _positional_args(rest[1:])
    if verb in _IMPLICIT_RESOURCE_TYPE:
        resource_type = _IMPLICIT_RESOURCE_TYPE[verb]
        resource_name = positional[0] if positional else None
    elif positional:
        # `kubectl get secret foo` -> resource_type=secret, resource_name=foo
        # `kubectl get pods` -> resource_type=pods, resource_name=None
        first = positional[0]
        if "/" in first:
            resource_type, resource_name = first.split("/", 1)
        else:
            resource_type = first
            if len(positional) > 1 and not positional[1].startswith("-"):
                resource_name = positional[1]

    if (
        verb == "get"
        and resource_type is not None
        and resource_type.rstrip("s") == "secret"
        and output_format
        and _VALUE_EXPOSING_OUTPUT.match(output_format)
    ):
        exposes_secret_value = True

    if verb == "rollout":
        sub = positional[0] if positional else ""
        # `kubectl rollout status ...` is read-only; restart/undo/etc change.
        if sub == "status":
            operation = OperationClass.READ
        elif sub in _ROLLOUT_CHANGE_SUBCOMMANDS:
            operation = OperationClass.CHANGE
        else:
            operation = OperationClass.CHANGE
        resource_type = f"rollout:{sub}" if sub else "rollout"
    elif verb == "exec":
        # Interactive exec on a real workload — here it's DESTRUCTIVE-tier by default so the
        # base policy matrix (ASK/BLOCK on non-sandbox) applies uniformly,
        # with prod-namespace handled explicitly in policies/*.yaml.
        operation = OperationClass.DESTRUCTIVE
    elif verb in _DESTRUCTIVE_VERBS:
        operation = OperationClass.DESTRUCTIVE
    elif verb in _CHANGE_VERBS:
        operation = OperationClass.CHANGE
    elif verb in _READ_VERBS:
        operation = OperationClass.READ
        if exposes_secret_value:
            operation = OperationClass.SECURITY_CRITICAL
    else:
        operation = OperationClass.CHANGE  # unknown verb: fail-safe, not READ

    blast_radius = _blast_radius(verb, resource_type, resource_name, namespace)

    return KubectlCommand(
        verb=verb,
        resource_type=resource_type,
        resource_name=resource_name,
        namespace=namespace,
        operation=operation,
        blast_radius=blast_radius,
        exposes_secret_value=exposes_secret_value,
    )


def _blast_radius(
    verb: str,
    resource_type: str | None,
    resource_name: str | None,
    namespace: str | None,
) -> str:
    rt = (resource_type or "").rstrip("s").lower()
    if verb in ("drain", "cordon", "uncordon", "taint") or rt == "node":
        return "cluster_or_database"
    if rt == "namespace":
        return "namespace_or_schema"
    if resource_name is None and rt not in ("", "secret", "configmap"):
        # e.g. `kubectl delete deployment` with no name = all of that type
        return "namespace_or_schema"
    if rt in ("deployment", "statefulset", "daemonset", "replicaset"):
        return "group"
    return "single"
