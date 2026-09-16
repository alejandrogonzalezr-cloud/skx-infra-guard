"""Claude Code hook protocol I/O.

Confirmed against the official hooks docs (research done 2026-09-15, see
docs/skydropx-architecture.md #7.2): the protocol is strictly binary.
PreToolUse (and friends) accept exactly:

    {"hookSpecificOutput": {"hookEventName": "...", "permissionDecision":
     "allow"|"deny", "permissionDecisionReason": "..."}}

There is no "ask" value in the schema. Exiting 0 with no output at all also
means allow (and defers to settings.json's static `permissions.ask`, if any
— see docs/skydropx-architecture.md #7.2 for why SKX Infra Guard does not
rely on that path). Any hook that raises an uncaught exception must still resolve to an explicit 
decision, as any non-0/2 exit would otherwise default to an implicit allow 
in the platform.
"""

from __future__ import annotations

import json
import sys


def read_hook_input() -> dict:
    """Truncated/malformed stdin must not be swallowed into `{}` — that
    silently resolves to no tool_name/no verdict downstream, which is an
    implicit ALLOW with zero audit trail. Let json.JSONDecodeError
    propagate; cli.py's top-level dispatch catches it the same way it
    catches any other evaluation-path exception and fails CLOSED instead."""
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    return json.loads(raw)


def emit_allow() -> None:
    sys.exit(0)


def emit_deny(hook_event_name: str, reason: str) -> None:
    payload = {
        "hookSpecificOutput": {
            "hookEventName": hook_event_name,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(payload))
    sys.exit(2)
