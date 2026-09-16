#!/usr/bin/env bash
# Claude Code PostToolUse hook shim — credential-in-output scanning and
# terraform-plan-content analysis (docs/policy-model.md #7). Can never
# block; see skx_infra_guard.cli._run_post_tool_use.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/dispatch.sh" post-tool-use
