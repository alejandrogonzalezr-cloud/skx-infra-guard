"""CLI entrypoint. Each Claude Code hook event gets its own subcommand; the
bash shims under hooks/ (see hooks/lib/dispatch.sh) invoke these with the
hook's stdin JSON piped straight through.

Also exposes `skx-guard evaluate` (dry-run, Skydropx brief section 29) and
`skx-guard approve` (resolves a pending ASK request, section 26).
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from skx_infra_guard.approval.sentinel import SentinelApprovalChannel
from skx_infra_guard.core.audit import AuditEngine
from skx_infra_guard.core.context import RequestContext, detect_environment
from skx_infra_guard.core.decision import Decision, EnvironmentTier, Verdict
from skx_infra_guard.core.normalizer import normalize
from skx_infra_guard.core.policy import PolicyEngine
from skx_infra_guard.domains import aws, database, file_guard, gcloud, git, helm, kubernetes, mongodb, post_audit, redis, secrets, shell_safety, terraform, web_guard
from skx_infra_guard.parsers import terraform as tf_parser
from skx_infra_guard.protocol import emit_allow, emit_deny, read_hook_input

_REPO_ROOT = Path(__file__).resolve().parents[2]

_COMMAND_DOMAINS = (kubernetes, terraform, database, git, gcloud, aws, redis, mongodb, helm, secrets)
_DECISION_RANK = {Decision.ALLOW: 0, Decision.ASK: 1, Decision.BLOCK: 2}


def _policies_dir() -> Path:
    return Path(os.environ.get("SKX_POLICIES_DIR", _REPO_ROOT / "policies"))


def _log_dir() -> Path:
    return Path(os.environ.get("SKX_LOG_DIR", os.environ.get("LOG_DIR", "~/.claude/logs"))).expanduser()


def _approvals_dir() -> Path:
    return _log_dir() / "skx-approvals"


def _session_id(payload: dict) -> str:
    return str(payload.get("session_id") or os.environ.get("CLAUDE_SESSION_ID") or "unknown")


def _requester(payload: dict) -> str:
    return str(payload.get("user") or os.environ.get("USER") or "unknown")


def _tool_input(payload: dict) -> dict:
    return payload.get("tool_input") or payload.get("input") or {}


def _tool_name(payload: dict) -> str:
    return str(payload.get("tool_name") or payload.get("name") or "")


def _extract_paths(tool_input: dict) -> list[str]:
    paths = []
    for key in ("path", "file_path"):
        if tool_input.get(key):
            paths.append(str(tool_input[key]))
    for edit in tool_input.get("edits") or []:
        if isinstance(edit, dict) and edit.get("path"):
            paths.append(str(edit["path"]))
    return paths


def _worse(a: Verdict | None, b: Verdict | None) -> Verdict | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if _DECISION_RANK[a.decision] >= _DECISION_RANK[b.decision] else b


def _evaluate_bash(command: str, cwd: str | None) -> Verdict | None:
    engine = PolicyEngine(_policies_dir())
    environment = detect_environment(command, cwd=cwd)
    ctx = RequestContext(tool_name="Bash", environment=environment, cwd=cwd)

    worst: Verdict | None = None
    for effective in normalize(command):
        text = effective.text
        verdict = shell_safety.evaluate(text, environment)
        if verdict is None:
            for domain_module in _COMMAND_DOMAINS:
                verdict = domain_module.evaluate(text, ctx, engine)
                if verdict is not None:
                    break
        if verdict is None:
            continue
        worst = _worse(worst, verdict)
        if worst is not None and worst.decision == Decision.BLOCK:
            break  # short-circuit, matching standard hook-chain behavior
    return worst


def _resolve_ask(verdict: Verdict, *, requester: str) -> tuple[Decision, str]:
    """ASK has no native equivalent in the Claude Code hook protocol
    (docs/skydropx-architecture.md #7.2) — resolve it via the Approval
    Engine: allow if a still-valid approval exists, otherwise deny with
    instructions for how to get one.
    """
    if verdict.decision != Decision.ASK:
        return verdict.decision, verdict.reason

    channel = SentinelApprovalChannel(_approvals_dir())
    rule_key = verdict.rule_id or f"{verdict.domain}:{verdict.operation}"
    resource_key = str(verdict.resource or "unspecified")

    if channel.has_valid_approval(rule_id=rule_key, resource=resource_key, requester=requester):
        return Decision.ALLOW, f"approved: {verdict.reason}"

    req = channel.request(
        rule_id=rule_key,
        resource=resource_key,
        requester=requester,
        reason=verdict.reason,
    )
    instructions = (
        f"{verdict.reason}\n\n"
        f"This operation requires approval. Request ID: {req.request_id}\n"
        f"An approver can run: skx-guard approve {req.request_id} --approver <email>"
    )
    return Decision.BLOCK, instructions


def _run_pre_tool_use(payload: dict) -> None:
    tool_name = _tool_name(payload)
    tool_input = _tool_input(payload)
    session_id = _session_id(payload)
    requester = _requester(payload)
    cwd = payload.get("cwd")
    audit = AuditEngine(_log_dir())

    verdict: Verdict | None = None

    if tool_name == "Bash":
        command = str(tool_input.get("command") or "")
        if command.strip():
            verdict = _evaluate_bash(command, cwd)
    elif tool_name in ("Write", "Edit", "MultiEdit"):
        environment = detect_environment("", cwd=cwd)
        paths = _extract_paths(tool_input)
        verdict = file_guard.evaluate_write(paths, environment)
    elif tool_name == "Read":
        environment = detect_environment("", cwd=cwd)
        paths = _extract_paths(tool_input)
        verdict = file_guard.evaluate_read(paths, environment)
    elif tool_name == "WebFetch":
        environment = detect_environment("", cwd=cwd)
        url = str(tool_input.get("url") or "")
        if url:
            verdict = web_guard.evaluate(url, environment)

    if verdict is None:
        emit_allow()
        return

    final_decision, reason = _resolve_ask(verdict, requester=requester)
    audit.log_verdict(verdict, tool=tool_name, session_id=session_id, actor="agent")

    if final_decision == Decision.BLOCK:
        emit_deny("PreToolUse", reason)
    else:
        emit_allow()


def _run_post_tool_use(payload: dict) -> None:
    tool_name = _tool_name(payload)
    tool_input = _tool_input(payload)
    output = str(payload.get("tool_response", {}).get("output") or payload.get("output") or "")
    session_id = _session_id(payload)
    audit = AuditEngine(_log_dir())

    if output:
        for hit in post_audit.scan(output):
            audit.log(
                _credential_event(hit.credential_type, tool_name, session_id)
            )

    command = str(tool_input.get("command") or "")
    if command and tf_parser.is_terraform_command(command):
        environment = detect_environment(command, cwd=payload.get("cwd"))
        ctx = RequestContext(tool_name=tool_name, environment=environment)
        plan_verdict = terraform.evaluate_plan_output(output, ctx, PolicyEngine(_policies_dir()))
        if plan_verdict is not None:
            audit.log_verdict(plan_verdict, tool=tool_name, session_id=session_id)

    # PostToolUse can never block — this hook's decision has no bearing on
    # an already-completed tool call.
    emit_allow()


def _credential_event(credential_type: str, tool: str, session_id: str):
    from skx_infra_guard.core.audit import AuditEvent, now_iso

    return AuditEvent(
        timestamp=now_iso(),
        event="alert",
        tool=tool,
        status="credential-detected",
        detail=f"{credential_type} found in tool output",
        environment="unknown",
        session=session_id,
        domain="post_audit",
    )


def _cmd_pre_tool_use(_args: argparse.Namespace) -> None:
    _run_pre_tool_use(read_hook_input())


def _cmd_post_tool_use(_args: argparse.Namespace) -> None:
    _run_post_tool_use(read_hook_input())


def _cmd_evaluate(args: argparse.Namespace) -> None:
    environment = EnvironmentTier(args.environment) if args.environment else None
    command = args.command
    env_override = {"CLAUDE_ENV": environment.value} if environment else os.environ

    verdict = None
    detected_env = detect_environment(command, env=env_override, cwd=os.getcwd())
    ctx = RequestContext(tool_name="Bash", environment=detected_env)
    engine = PolicyEngine(_policies_dir())

    for effective in normalize(command):
        v = shell_safety.evaluate(effective.text, detected_env)
        if v is None:
            for domain_module in _COMMAND_DOMAINS:
                v = domain_module.evaluate(effective.text, ctx, engine)
                if v is not None:
                    break
        verdict = _worse(verdict, v)

    print(f"Environment: {detected_env.value}")
    if verdict is None:
        print("Domain: none matched")
        print("Decision: ALLOW (no applicable rule)")
        return

    final_decision, reason = _resolve_ask(verdict, requester=_requester({}))
    print(f"Domain: {verdict.domain}")
    print(f"Operation: {verdict.operation.value if verdict.operation else 'unknown'}")
    print(f"Resource: {verdict.resource}")
    print(f"Risk: {verdict.risk.value.upper()}")
    print(f"Rule: {verdict.rule_id or '(default matrix)'}")
    print(f"Decision: {final_decision.value.upper()}")
    print(f"Reason:\n{reason}")


def _cmd_approve(args: argparse.Namespace) -> None:
    channel = SentinelApprovalChannel(_approvals_dir())
    req = channel.approve(args.request_id, args.approver)
    print(f"Approved {req.request_id} for {req.requester} (rule={req.rule_id}, resource={req.resource})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skx-guard")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("pre-tool-use").set_defaults(func=_cmd_pre_tool_use)
    sub.add_parser("post-tool-use").set_defaults(func=_cmd_post_tool_use)

    evaluate_parser = sub.add_parser("evaluate", help="Dry-run: classify a command without executing it")
    evaluate_parser.add_argument("command")
    evaluate_parser.add_argument("--environment", choices=[e.value for e in EnvironmentTier], default=None)
    evaluate_parser.set_defaults(func=_cmd_evaluate)

    approve_parser = sub.add_parser("approve", help="Approve a pending ASK request")
    approve_parser.add_argument("request_id")
    approve_parser.add_argument("--approver", required=True)
    approve_parser.set_defaults(func=_cmd_approve)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main(sys.argv[1:])
