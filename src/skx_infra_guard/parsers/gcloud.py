"""GCP (`gcloud`) command parser.

Implements a structured parse of `gcloud <service> [resource nouns...] <verb> [args...]`,
covering the services explicit to Skydropx architecture (compute, container, sql, logging, 
monitoring, iam, secrets, storage, kms, and redis/memorystore), which are constantly 
present in Skydropx's real GCP usage.

gcloud's own grammar doesn't put the verb in a fixed position (`gcloud
compute instances create my-vm` vs `gcloud projects add-iam-policy-binding
PROJECT_ID`), so this scans the positional tokens for the last one that
matches a known verb, rather than assuming a fixed slot.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from skx_infra_guard.core.decision import OperationClass

_READ_VERBS = {
    "describe", "list", "get", "export", "show", "get-iam-policy",
    "get-config", "get-value",
}
_CHANGE_VERBS = {
    "create", "update", "patch", "set", "import", "add", "enable", "disable",
    "start", "stop", "resume", "suspend", "deploy", "upload", "restore",
    "clone", "resize", "rename", "move", "copy", "rotate",
}
_DESTRUCTIVE_VERBS = {"delete", "destroy", "remove", "purge", "undeploy"}

# Verbs that mutate IAM policy — these are security-critical no matter what
# service noun they're attached to (`gcloud projects add-iam-policy-binding`,
# `gcloud kms keys add-iam-policy-binding`, `gcloud secrets
# add-iam-policy-binding` all carry the same risk).
_IAM_MUTATION_VERBS = {"add-iam-policy-binding", "remove-iam-policy-binding", "set-iam-policy"}

# `gcloud secrets versions access` returns the actual secret value in
# plaintext; `describe`/`list` only return metadata — same distinction as
# `kubectl get secret -o yaml` vs plain `get secret` (docs/policy-model.md #11).
_SECRET_VALUE_ACCESS_SERVICES = {"secrets", "secretmanager"}
_SECRET_VALUE_ACCESS_VERBS = {"access"}

_ALL_VERBS = (
    _READ_VERBS | _CHANGE_VERBS | _DESTRUCTIVE_VERBS | _IAM_MUTATION_VERBS | _SECRET_VALUE_ACCESS_VERBS
)


@dataclass
class GcloudCommand:
    service: str
    verb: str | None
    operation: OperationClass
    touches_iam: bool
    touches_secrets: bool
    resource_hint: str | None  # e.g. "instances", "buckets" — best-effort noun


def is_gcloud_command(command: str) -> bool:
    return bool(re.match(r"^\s*gcloud\s", command))


def parse(command: str) -> GcloudCommand | None:
    if not is_gcloud_command(command):
        return None

    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    positional: list[str] = []
    for tok in tokens[1:]:
        if tok.startswith("-"):
            break
        positional.append(tok)

    if not positional:
        return None

    service = positional[0].lower()

    verb: str | None = None
    verb_index = -1
    for i, tok in enumerate(positional):
        if tok.lower() in _ALL_VERBS:
            verb = tok.lower()
            verb_index = i

    resource_hint = positional[1] if len(positional) > 1 and verb_index != 1 else None

    touches_iam = verb in _IAM_MUTATION_VERBS
    touches_secrets = service in _SECRET_VALUE_ACCESS_SERVICES and verb in _SECRET_VALUE_ACCESS_VERBS

    if touches_iam or touches_secrets:
        operation = OperationClass.SECURITY_CRITICAL
    elif verb in _DESTRUCTIVE_VERBS:
        operation = OperationClass.DESTRUCTIVE
    elif verb in _CHANGE_VERBS:
        operation = OperationClass.CHANGE
    elif verb in _READ_VERBS:
        operation = OperationClass.READ
    else:
        # No recognized verb at all (e.g. `gcloud auth login`, or a gcloud
        # subcommand this parser doesn't know yet) — fail-safe to CHANGE,
        # never silently READ.
        operation = OperationClass.CHANGE

    return GcloudCommand(
        service=service,
        verb=verb,
        operation=operation,
        touches_iam=touches_iam,
        touches_secrets=touches_secrets,
        resource_hint=resource_hint,
    )
