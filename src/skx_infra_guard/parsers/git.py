"""Git command parser, turned into a typed result instead of a
sequence of independent `if` blocks that each emit their own block message.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass

from skx_infra_guard.core.decision import OperationClass

_DEFAULT_PROTECTED = ("main", "master", "release", "hotfix", "production")


@dataclass
class GitCommand:
    subcommand: str
    resource_type: str | None  # None, or one of the always-flagged patterns below
    operation: OperationClass


def is_git_command(command: str) -> bool:
    return bool(re.match(r"^\s*git\s", command))


def _protected_branches() -> tuple[str, ...]:
    raw = os.environ.get("PROTECTED_BRANCHES", ":".join(_DEFAULT_PROTECTED))
    return tuple(b for b in raw.split(":") if b)


def _pushed_branch(command: str) -> str | None:
    m = re.search(r"git\s+push\s+[\w.\-]+\s+([\w/.\-]+)", command)
    if m:
        return m.group(1).split(":")[-1]
    m = re.search(r"HEAD:([\w/.\-]+)", command)
    if m:
        return m.group(1)
    return None


def parse(command: str) -> GitCommand | None:
    if not is_git_command(command):
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    rest = tokens[1:]
    if not rest:
        return None
    subcommand = rest[0]

    if subcommand == "push":
        if re.search(r"(--force|(?<!\S)-f(?!\S))", command):
            return GitCommand("push", "force_push", OperationClass.DESTRUCTIVE)
        if "--delete" in command:
            return GitCommand("push", "delete_remote_branch", OperationClass.DESTRUCTIVE)
        branch = _pushed_branch(command)
        if branch and branch in _protected_branches():
            return GitCommand("push", "protected_branch_push", OperationClass.DESTRUCTIVE)
        return GitCommand("push", None, OperationClass.CHANGE)

    if subcommand == "reset" and "--hard" in command:
        return GitCommand("reset", "hard_reset", OperationClass.DESTRUCTIVE)

    if subcommand == "clean" and re.search(r"-\w*f", command):
        return GitCommand("clean", "clean_force", OperationClass.DESTRUCTIVE)

    if "--no-verify" in command:
        return GitCommand(subcommand, "no_verify", OperationClass.DESTRUCTIVE)

    if subcommand in ("status", "log", "diff", "show", "branch", "remote", "config", "rev-parse", "fetch"):
        # `branch -D` is a local force-delete — keep that distinction as CHANGE, not
        # DESTRUCTIVE.
        if subcommand == "branch" and "-D" in tokens:
            return GitCommand("branch", "force_delete_local_branch", OperationClass.CHANGE)
        return GitCommand(subcommand, None, OperationClass.READ)

    if subcommand in ("commit", "add", "checkout", "stash", "merge", "rebase", "tag", "pull"):
        return GitCommand(subcommand, None, OperationClass.CHANGE)

    return GitCommand(subcommand, None, OperationClass.CHANGE)
