#!/usr/bin/env bash
# Claude Code PreToolUse hook shim. Registered against Bash, Write|Edit|
# MultiEdit, WebFetch, and Read in settings.json — routing by tool_name
# happens inside the Python core (skx_infra_guard.cli), not here, so one
# shim covers every tool (docs/skydropx-architecture.md #2).
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/dispatch.sh" pre-tool-use
