"""Helm command parser.

Implements a robust parser for Helm command operations, mapping them onto
this project's existing OperationClass tiers (READ/CHANGE/DESTRUCTIVE),
so no new policy machinery is needed — just a parser.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from skx_infra_guard.core.decision import OperationClass

_READ_SUBCOMMANDS = {
    "template", "diff", "get", "history", "list", "status", "show", "lint",
    "search", "verify", "version", "env", "inspect",
}
_CHANGE_SUBCOMMANDS = {
    "install", "upgrade", "repo", "dependency", "package", "push", "pull",
    "plugin", "registry", "create",
}
_DESTRUCTIVE_SUBCOMMANDS = {"uninstall", "delete"}
# rollback reverts a release to a prior revision — same tier as upgrade per
# the brief ("rollback → ASK", not "BLOCK"), so it's CHANGE, not DESTRUCTIVE.
_ROLLBACK_SUBCOMMAND = "rollback"


@dataclass
class HelmCommand:
    subcommand: str
    operation: OperationClass
    release_name: str | None


def is_helm_command(command: str) -> bool:
    return bool(re.match(r"^\s*helm\s", command))


def parse(command: str) -> HelmCommand | None:
    if not is_helm_command(command):
        return None

    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    rest = tokens[1:]
    if not rest:
        return None

    subcommand = rest[0]
    positional = [t for t in rest[1:] if not t.startswith("-")]
    release_name = positional[0] if positional else None

    if subcommand == _ROLLBACK_SUBCOMMAND:
        operation = OperationClass.CHANGE
    elif subcommand in _DESTRUCTIVE_SUBCOMMANDS:
        operation = OperationClass.DESTRUCTIVE
    elif subcommand in _CHANGE_SUBCOMMANDS:
        operation = OperationClass.CHANGE
    elif subcommand in _READ_SUBCOMMANDS:
        operation = OperationClass.READ
    else:
        operation = OperationClass.CHANGE  # unknown subcommand: fail-safe

    return HelmCommand(subcommand=subcommand, operation=operation, release_name=release_name)
