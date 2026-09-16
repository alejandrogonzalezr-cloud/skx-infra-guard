"""AWS CLI command parser.

Provides comprehensive coverage of AWS CLI operations (destructive operations,
IAM mutations, `sts assume-role`, etc.) in alignment with Skydropx cloud
infrastructure governance policies.

AWS CLI verbs are single hyphenated tokens (`describe-instances`,
`create-user`, `terminate-instances`) rather than gcloud's separate
"noun verb" tokens, so classification is by prefix match on that one
token instead of scanning for a known word.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from skx_infra_guard.core.decision import OperationClass

_READ_PREFIXES = ("describe-", "list-", "get-", "head-")
_READ_VERBS_EXACT = {"ls"}
_CHANGE_PREFIXES = (
    "create-", "put-", "update-", "attach-", "enable-", "start-", "modify-",
    "add-", "tag-", "run-", "assign-", "register-", "associate-",
)
_DESTRUCTIVE_PREFIXES = (
    "delete-", "terminate-", "remove-", "detach-", "revoke-", "deregister-",
    "disassociate-",
)
_DESTRUCTIVE_VERBS_EXACT = {"rb"}  # `aws s3 rb` — remove bucket

# `aws iam <verb>` — mutating any of these is a privilege/identity change
# regardless of what the prefix-based classifier above would say, ensuring
# that unconditional "aws iam create/delete/attach/detach/put/add/remove/update"
# blocks are enforced.
_IAM_MUTATION_PREFIXES = (
    "create-", "delete-", "attach-", "detach-", "put-", "add-", "remove-", "update-",
)


@dataclass
class AwsCommand:
    service: str
    verb: str | None
    operation: OperationClass
    touches_iam: bool


def is_aws_command(command: str) -> bool:
    return bool(re.match(r"^\s*aws\s", command))


def parse(command: str) -> AwsCommand | None:
    if not is_aws_command(command):
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
    verb = positional[1].lower() if len(positional) > 1 else None

    # `aws sts assume-role` — privilege escalation risk, always critical,
    # regardless of prefix-based classification (which would call it a
    # plain CHANGE since it starts with neither create-/delete-/etc.).
    if service == "sts" and verb == "assume-role":
        return AwsCommand(service=service, verb=verb, operation=OperationClass.SECURITY_CRITICAL, touches_iam=True)

    if service == "iam" and verb and verb.startswith(_IAM_MUTATION_PREFIXES):
        return AwsCommand(service=service, verb=verb, operation=OperationClass.SECURITY_CRITICAL, touches_iam=True)

    if verb is None:
        operation = OperationClass.CHANGE  # fail-safe
    elif verb in _READ_VERBS_EXACT or verb.startswith(_READ_PREFIXES):
        operation = OperationClass.READ
    elif verb in _DESTRUCTIVE_VERBS_EXACT or verb.startswith(_DESTRUCTIVE_PREFIXES):
        operation = OperationClass.DESTRUCTIVE
    elif verb.startswith(_CHANGE_PREFIXES):
        operation = OperationClass.CHANGE
    else:
        operation = OperationClass.CHANGE  # unknown verb shape: fail-safe

    return AwsCommand(service=service, verb=verb, operation=operation, touches_iam=False)
