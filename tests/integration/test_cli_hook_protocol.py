"""End-to-end test of the actual Claude Code hook contract: stdin JSON in,
exit code + stdout JSON out (docs/skydropx-architecture.md #7.2). Runs the
real CLI entrypoint as a subprocess so nothing about sys.exit()/stdout
plumbing is mocked away.
"""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_hook(event: str, payload: dict, tmp_path, env_overrides: dict | None = None):
    env = {
        "PATH": "/usr/bin:/bin",
        "SKX_LOG_DIR": str(tmp_path / "logs"),
        "SKX_POLICIES_DIR": str(REPO_ROOT / "policies"),
        "CLAUDE_ENV": "production",
    }
    if env_overrides:
        env.update(env_overrides)

    result = subprocess.run(
        [sys.executable, "-m", "skx_infra_guard.cli", event],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env={**env, "PYTHONPATH": str(REPO_ROOT / "src")},
    )
    return result


def test_pre_tool_use_blocks_kubectl_delete(tmp_path):
    payload = {"tool_name": "Bash", "tool_input": {"command": "kubectl delete namespace production"}}
    result = _run_hook("pre-tool-use", payload, tmp_path)
    assert result.returncode == 2
    body = json.loads(result.stdout)
    assert body["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "kubectl delete" in body["hookSpecificOutput"]["permissionDecisionReason"]


def test_pre_tool_use_blocks_the_bash_dash_c_bypass(tmp_path):
    payload = {"tool_name": "Bash", "tool_input": {"command": 'bash -c "kubectl delete namespace production"'}}
    result = _run_hook("pre-tool-use", payload, tmp_path)
    assert result.returncode == 2


def test_pre_tool_use_allows_safe_read(tmp_path):
    payload = {"tool_name": "Bash", "tool_input": {"command": "kubectl get pods"}}
    result = _run_hook("pre-tool-use", payload, tmp_path)
    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_pre_tool_use_blocks_sensitive_file_read(tmp_path):
    payload = {"tool_name": "Read", "tool_input": {"path": str(tmp_path / ".aws" / "credentials")}}
    result = _run_hook("pre-tool-use", payload, tmp_path)
    assert result.returncode == 2


def test_pre_tool_use_blocks_ssrf_webfetch(tmp_path):
    payload = {"tool_name": "WebFetch", "tool_input": {"url": "http://169.254.169.254/latest/meta-data/"}}
    result = _run_hook("pre-tool-use", payload, tmp_path)
    assert result.returncode == 2


def test_audit_log_is_written(tmp_path):
    payload = {"tool_name": "Bash", "tool_input": {"command": "kubectl delete namespace production"}}
    _run_hook("pre-tool-use", payload, tmp_path)
    audit_log = tmp_path / "logs" / "audit.jsonl"
    assert audit_log.is_file()
    lines = audit_log.read_text().strip().splitlines()
    assert len(lines) >= 1
    event = json.loads(lines[-1])
    assert event["status"] == "block"
    assert event["domain"] == "kubernetes"


def test_pre_tool_use_malformed_json_fails_closed_not_crashes(tmp_path):
    # A truncated/malformed stdin payload used to be silently swallowed
    # into `{}` by read_hook_input(), which meant no tool_name, no verdict,
    # and a silent ALLOW with zero audit trail. It must now fail CLOSED
    # (deny, exit 2), not silently allow — and not crash with a traceback
    # either (found in the 2026-09 review).
    result = subprocess.run(
        [sys.executable, "-m", "skx_infra_guard.cli", "pre-tool-use"],
        input="{not valid json at all",
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env={
            "PATH": "/usr/bin:/bin",
            "SKX_LOG_DIR": str(tmp_path / "logs"),
            "SKX_POLICIES_DIR": str(REPO_ROOT / "policies"),
            "CLAUDE_ENV": "production",
            "PYTHONPATH": str(REPO_ROOT / "src"),
        },
    )
    assert result.returncode == 2
    body = json.loads(result.stdout)
    assert body["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_pre_tool_use_audit_engine_crash_fails_closed_not_implicit_allow(tmp_path):
    # `_run_pre_tool_use` used to have no exception handling at all: any
    # uncaught exception on the evaluation path (here, AuditEngine.__init__
    # failing its own mkdir because SKX_LOG_DIR's parent is a regular file,
    # not a directory) crashed the process with a non-0/2 exit, which the
    # Claude Code hook platform then defaults to an implicit ALLOW — for a
    # command that should have been BLOCKed (found in the 2026-09 review).
    blocker = tmp_path / "not_a_directory"
    blocker.write_text("x")
    payload = {"tool_name": "Bash", "tool_input": {"command": "kubectl delete namespace production"}}
    result = _run_hook(
        "pre-tool-use", payload, tmp_path, env_overrides={"SKX_LOG_DIR": str(blocker / "logs")}
    )
    assert result.returncode == 2
    body = json.loads(result.stdout)
    assert body["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_pre_tool_use_unknown_tool_name_asks_in_production_not_silent_allow(tmp_path):
    # tool_name dispatch had no default branch: anything other than
    # Bash/Write/Edit/MultiEdit/Read/WebFetch (e.g. an MCP tool call) fell
    # through with verdict=None and was auto-allowed with no audit trail.
    payload = {"tool_name": "mcp__docker__exec_command", "tool_input": {}}
    result = _run_hook("pre-tool-use", payload, tmp_path)
    # ASK with no existing approval resolves to BLOCK, same as any other
    # domain's ASK path.
    assert result.returncode == 2


def test_pre_tool_use_unknown_tool_name_allowed_in_sandbox(tmp_path):
    payload = {"tool_name": "mcp__docker__exec_command", "tool_input": {}}
    result = _run_hook("pre-tool-use", payload, tmp_path, env_overrides={"CLAUDE_ENV": "sandbox"})
    assert result.returncode == 0


def test_pre_tool_use_unknown_tool_name_writes_audit_event(tmp_path):
    payload = {"tool_name": "mcp__docker__exec_command", "tool_input": {}}
    _run_hook("pre-tool-use", payload, tmp_path, env_overrides={"CLAUDE_ENV": "sandbox"})
    audit_log = tmp_path / "logs" / "audit.jsonl"
    assert audit_log.is_file()
    event = json.loads(audit_log.read_text().strip().splitlines()[-1])
    assert event["domain"] == "unknown_tool"
