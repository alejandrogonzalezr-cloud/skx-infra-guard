"""MongoDB command parser.

Implements a dedicated domain parser for MongoDB commands (JS-method shell
syntax) rather than routing them through a generic SQL parser, ensuring
accurate risk and policy classification for Mongo operations
(docs/skydropx-architecture.md #8).
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from skx_infra_guard.core.decision import OperationClass

_READ_METHODS = {
    "find", "findone", "countdocuments", "count", "aggregate", "distinct",
    "getindexes", "stats", "getcollectionnames", "explain",
}
_CHANGE_METHODS = {
    "insertone", "insertmany", "insert", "updateone", "updatemany", "update",
    "replaceone", "createindex", "createindexes", "createcollection",
    "renamecollection", "bulkwrite", "findoneandupdate", "findoneandreplace",
}
_DESTRUCTIVE_METHODS = {
    "deleteone", "deletemany", "remove", "drop", "dropindex", "dropindexes",
    "findoneanddelete",
}

_EMPTY_FILTER_RE = re.compile(r"\{\s*\}")
_METHOD_CALL_RE = re.compile(r"\.([A-Za-z][A-Za-z0-9_]*)\s*\(([^()]*)\)")
_DROP_DATABASE_RE = re.compile(r"\bdropDatabase\s*\(", re.IGNORECASE)


@dataclass
class MongoCommand:
    methods_found: tuple[str, ...]
    operation: OperationClass
    always_blocked: bool
    always_blocked_reason: str | None


def is_mongo_command(command: str) -> bool:
    return bool(re.match(r"^\s*(mongosh|mongo)\s", command))


def _extract_js(command: str) -> str:
    """Pulls the JS payload out of `mongosh ... --eval '...'`. Falls back to
    the raw command, matching the same conservative philosophy as
    parsers/shell.py::extract_inline_sql — analyze the whole string rather
    than give up if there's no `--eval` flag."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return command

    for flag in ("--eval",):
        if flag in tokens:
            idx = tokens.index(flag)
            if idx + 1 < len(tokens):
                return tokens[idx + 1]

    return command


def parse(command: str) -> MongoCommand | None:
    if not is_mongo_command(command):
        return None

    js = _extract_js(command)

    if _DROP_DATABASE_RE.search(js):
        return MongoCommand(
            methods_found=("dropDatabase",),
            operation=OperationClass.DESTRUCTIVE,
            always_blocked=True,
            always_blocked_reason="db.dropDatabase() destroys the entire database",
        )

    calls = _METHOD_CALL_RE.findall(js)
    methods = tuple(name for name, _args in calls)

    for name, args in calls:
        if name.lower() in ("deletemany", "remove", "updatemany") and _EMPTY_FILTER_RE.match(args.strip() or "{}"):
            return MongoCommand(
                methods_found=methods or (name,),
                operation=OperationClass.DESTRUCTIVE,
                always_blocked=True,
                always_blocked_reason=f"{name}({{}}) with an empty filter matches every document",
            )

    if not methods:
        # Looks like a mongo shell invocation but no recognizable method
        # call (e.g. bare `mongosh` for an interactive session, or a
        # connection-string-only invocation) — fail-safe, never READ.
        return MongoCommand(
            methods_found=(), operation=OperationClass.CHANGE, always_blocked=False, always_blocked_reason=None
        )

    worst = OperationClass.READ
    for name in methods:
        lname = name.lower()
        if lname in _DESTRUCTIVE_METHODS:
            worst = OperationClass.DESTRUCTIVE
            break
        if lname in _CHANGE_METHODS and worst != OperationClass.DESTRUCTIVE:
            worst = OperationClass.CHANGE
        elif lname not in _READ_METHODS and worst == OperationClass.READ:
            worst = OperationClass.CHANGE  # unrecognized method: fail-safe

    return MongoCommand(methods_found=methods, operation=worst, always_blocked=False, always_blocked_reason=None)
