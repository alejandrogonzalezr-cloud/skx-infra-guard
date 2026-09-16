"""Approval Engine — file-based channel.

Implements a robust file-based sentinel-file pattern for specific cases
(terraform-plan-approved.sentinel, tests-passed-*.sentinel) into a proper
request/approve/expire flow that works for ANY rule, per Skydropx brief
section 26: request, requester, approver, timestamp, reason, expiration, result.

This is the only channel implemented in the MVP. It is deliberately built
behind a small interface (`ApprovalChannel`) so Slack/GitHub/PagerDuty/Web UI
channels (section 26) can be added later without touching the Policy Engine.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

DEFAULT_TTL_SECONDS = 30 * 60  # 30 minutes default for test-sentinel.


@dataclass
class ApprovalRequest:
    request_id: str
    rule_id: str
    resource: str
    requester: str
    reason: str
    created_at: float
    ttl_seconds: int
    approver: str | None = None
    approved_at: float | None = None

    def is_approved(self, now: float | None = None) -> bool:
        if self.approver is None or self.approved_at is None:
            return False
        now = time.time() if now is None else now
        return (now - self.approved_at) < self.ttl_seconds


def _make_request_id(rule_id: str, resource: str, requester: str) -> str:
    digest = hashlib.sha256(f"{rule_id}:{resource}:{requester}".encode()).hexdigest()
    return digest[:16]


class SentinelApprovalChannel:
    """Approval requests/records stored as one JSON file per request under
    `store_dir`. Simple, inspectable, no external service required — matches
    the design philosophy of "no extra daemon, just files"."""

    def __init__(self, store_dir: Path):
        self.store_dir = store_dir
        self.store_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, request_id: str) -> Path:
        return self.store_dir / f"{request_id}.json"

    def request(
        self,
        *,
        rule_id: str,
        resource: str,
        requester: str,
        reason: str,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> ApprovalRequest:
        request_id = _make_request_id(rule_id, resource, requester)
        existing = self.get(request_id)
        if existing is not None:
            return existing
        req = ApprovalRequest(
            request_id=request_id,
            rule_id=rule_id,
            resource=resource,
            requester=requester,
            reason=reason,
            created_at=time.time(),
            ttl_seconds=ttl_seconds,
        )
        self._save(req)
        return req

    def get(self, request_id: str) -> ApprovalRequest | None:
        path = self._path(request_id)
        if not path.is_file():
            return None
        return ApprovalRequest(**json.loads(path.read_text()))

    def approve(self, request_id: str, approver: str) -> ApprovalRequest:
        req = self.get(request_id)
        if req is None:
            raise KeyError(f"no such approval request: {request_id}")
        req.approver = approver
        req.approved_at = time.time()
        self._save(req)
        return req

    def has_valid_approval(self, *, rule_id: str, resource: str, requester: str) -> bool:
        request_id = _make_request_id(rule_id, resource, requester)
        req = self.get(request_id)
        return req is not None and req.is_approved()

    def _save(self, req: ApprovalRequest) -> None:
        self._path(req.request_id).write_text(json.dumps(asdict(req)))
