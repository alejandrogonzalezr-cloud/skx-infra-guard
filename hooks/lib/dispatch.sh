#!/usr/bin/env bash
# Shared launcher for every SKX Infra Guard hook shim.
# Finds skx-guard on PATH first (the normal case after `pip install .` or
# `pipx install .`); falls back to the project-local virtualenv installed by
# install.sh so a fresh clone works without any extra PATH setup.

set -euo pipefail

if command -v skx-guard &>/dev/null; then
  exec skx-guard "$@"
fi

SKX_HOME="${SKX_INFRA_GUARD_HOME:-$HOME/.claude/skx-infra-guard}"
if [[ -x "$SKX_HOME/.venv/bin/skx-guard" ]]; then
  exec "$SKX_HOME/.venv/bin/skx-guard" "$@"
fi

# Fail-safe (docs/threat-model.md #3): if we can't even find our own
# binary, don't let Claude Code silently treat that as allow. PreToolUse
# fails closed with an explicit deny; PostToolUse/other events can't block
# at all, so there's nothing safer to do there than exit 0 and let the
# missing-install become visible some other way (Claude Code's own hook
# error surfacing, or a monitoring check on skx-guard's presence).
event="${1:-}"
if [[ "$event" == "pre-tool-use" ]]; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"SKX Infra Guard is not installed correctly — skx-guard was not found on PATH or at '"$SKX_HOME"'/.venv/bin/skx-guard. Run install.sh."}}'
  exit 2
fi
exit 0
