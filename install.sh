#!/usr/bin/env bash
# install.sh — installs SKX Infra Guard for Claude Code.
#
# What it does:
#   1. Copies this repo (source + policies) to ~/.claude/skx-infra-guard
#   2. Creates a dedicated virtualenv there and pip-installs the package
#   3. Copies the hook shims to ~/.claude/hooks/
#   4. Backs up and offers to merge settings.json
#   5. Runs the test suite as a smoke test
#
# Usage: bash install.sh [--skip-tests] [--dry-run]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKX_HOME="${SKX_INFRA_GUARD_HOME:-$HOME/.claude/skx-infra-guard}"
CLAUDE_DIR="$HOME/.claude"
HOOKS_DEST="$CLAUDE_DIR/hooks"
SETTINGS_DEST="$CLAUDE_DIR/settings.json"

SKIP_TESTS=false
DRY_RUN=false
for arg in "$@"; do
  case "$arg" in
    --skip-tests) SKIP_TESTS=true ;;
    --dry-run) DRY_RUN=true ;;
    -h|--help)
      echo "Usage: bash install.sh [--skip-tests] [--dry-run]"
      exit 0
      ;;
  esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }
log_section() { echo -e "\n${BLUE}=== $* ===${NC}"; }

log_section "Preflight checks"

if ! command -v python3 &>/dev/null; then
  log_error "python3 is required but not installed."
  exit 1
fi
PY_VERSION="$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')"
log_info "python3: $PY_VERSION"

log_section "Step 1: Copying source to $SKX_HOME"
if [[ "$DRY_RUN" == "true" ]]; then
  echo -e "${YELLOW}[DRY-RUN]${NC} Would copy $SCRIPT_DIR -> $SKX_HOME"
else
  mkdir -p "$SKX_HOME"
  cp -r "$SCRIPT_DIR/src" "$SCRIPT_DIR/policies" "$SCRIPT_DIR/pyproject.toml" "$SKX_HOME/"
  log_info "Copied source + policies to $SKX_HOME"
fi

log_section "Step 2: Creating virtualenv and installing"
if [[ "$DRY_RUN" == "true" ]]; then
  echo -e "${YELLOW}[DRY-RUN]${NC} Would create $SKX_HOME/.venv and pip install -e $SKX_HOME"
else
  python3 -m venv "$SKX_HOME/.venv"
  "$SKX_HOME/.venv/bin/pip" install --quiet --upgrade pip
  "$SKX_HOME/.venv/bin/pip" install --quiet "$SKX_HOME"
  log_info "Installed skx-infra-guard into $SKX_HOME/.venv"
fi

log_section "Step 3: Installing hook shims"
if [[ "$DRY_RUN" == "true" ]]; then
  echo -e "${YELLOW}[DRY-RUN]${NC} Would copy hooks/ -> $HOOKS_DEST"
else
  mkdir -p "$HOOKS_DEST/lib"
  cp "$SCRIPT_DIR/hooks/pre-tool-use.sh" "$SCRIPT_DIR/hooks/post-tool-use.sh" "$HOOKS_DEST/"
  cp "$SCRIPT_DIR/hooks/lib/dispatch.sh" "$HOOKS_DEST/lib/"
  chmod +x "$HOOKS_DEST"/*.sh "$HOOKS_DEST/lib/dispatch.sh"
  log_info "Hook shims installed to $HOOKS_DEST"
fi

log_section "Step 4: Settings configuration"
if [[ -f "$SETTINGS_DEST" ]]; then
  if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "${YELLOW}[DRY-RUN]${NC} Would back up $SETTINGS_DEST"
  else
    BACKUP="${SETTINGS_DEST}.bak.$(date +%Y%m%d-%H%M%S)"
    cp "$SETTINGS_DEST" "$BACKUP"
    log_warn "Backed up existing settings.json -> $BACKUP"
  fi
  echo ""
  log_warn "settings.json already exists — merge manually to avoid losing existing configuration."
  echo "  diff $SETTINGS_DEST $SCRIPT_DIR/settings.json"
  echo "  Add the missing 'hooks', 'env', and 'permissions' entries from the new file."
else
  if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "${YELLOW}[DRY-RUN]${NC} Would copy settings.json to $SETTINGS_DEST"
  else
    mkdir -p "$CLAUDE_DIR"
    cp "$SCRIPT_DIR/settings.json" "$SETTINGS_DEST"
    log_info "Installed settings.json to $SETTINGS_DEST"
  fi
fi

log_section "Step 5: Smoke tests"
if [[ "$SKIP_TESTS" == "true" ]]; then
  log_warn "Tests skipped (--skip-tests)"
elif [[ "$DRY_RUN" == "true" ]]; then
  echo -e "${YELLOW}[DRY-RUN]${NC} Would run: $SKX_HOME/.venv/bin/pip install pytest && pytest"
else
  "$SKX_HOME/.venv/bin/pip" install --quiet pytest
  if (cd "$SCRIPT_DIR" && SKX_POLICIES_DIR="$SCRIPT_DIR/policies" "$SKX_HOME/.venv/bin/python" -m pytest -q); then
    log_info "Smoke tests passed!"
  else
    log_warn "Some tests failed — review output above before relying on this install."
  fi
fi

log_section "Installation Summary"
if [[ "$DRY_RUN" == "true" ]]; then
  echo -e "${YELLOW}DRY RUN completed - no changes made${NC}"
else
  log_info "Installed to: $SKX_HOME"
  log_info "Hooks:        $HOOKS_DEST"
  echo ""
  echo "Next steps:"
  echo "  1. Set your environment tier in $SETTINGS_DEST (CLAUDE_ENV: sandbox|dev|qa|staging|production)"
  echo "  2. Dry-run a command: $SKX_HOME/.venv/bin/skx-guard evaluate 'kubectl delete namespace production'"
  echo "  3. Watch the audit log: tail -f ~/.claude/logs/audit.jsonl | jq ."
fi
